use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::sleep;
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub access_token: String,
    pub refresh_token: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiscordGuild {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
    pub owner: bool,
    #[serde(deserialize_with = "deserialize_permissions")]
    pub permissions: String,
    pub features: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub discriminator: String,
    pub avatar: Option<String>,
    #[allow(dead_code)]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DiscordTokenResponse {
    pub access_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    #[allow(dead_code)]
    pub expires_in: u64,
    pub refresh_token: String,
    #[allow(dead_code)]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscordRateLimitResponse {
    pub retry_after: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AuthCallbackQuery {
    pub code: Option<String>,
    pub error: Option<String>,
    #[allow(dead_code)]
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub discriminator: String,
    pub avatar: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GuildsResponse {
    pub guilds: Vec<DiscordGuild>,
    pub new_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Clone)]
pub struct AuthState {
    pub http_client: Client,
    pub jwt_secret: String,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    pub frontend_url: String,
}

fn deserialize_permissions<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct PermissionsVisitor;

    impl<'de> Visitor<'de> for PermissionsVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or integer representing permissions")
        }

        fn visit_str<E>(self, value: &str) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_u64<E>(self, value: u64) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(value.to_string())
        }

        fn visit_i64<E>(self, value: i64) -> Result<String, E>
        where
            E: de::Error,
        {
            Ok(value.to_string())
        }
    }

    deserializer.deserialize_any(PermissionsVisitor)
}

pub fn create_auth_router() -> Router<AuthState> {
    Router::new()
        .route("/discord", get(discord_login))
        .route("/discord/callback", get(discord_callback))
        .route("/verify", post(verify_token))
        .route("/me", get(get_current_user))
        .route("/guilds", get(get_user_guilds))
}

pub async fn discord_login(State(state): State<AuthState>) -> impl IntoResponse {
    let mut auth_url = Url::parse("https://discord.com/api/oauth2/authorize").unwrap();

    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &state.discord_client_id)
        .append_pair("redirect_uri", &state.discord_redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "identify email guilds");

    Redirect::temporary(auth_url.as_str())
}

pub async fn discord_callback(
    Query(params): Query<AuthCallbackQuery>,
    State(state): State<AuthState>,
) -> impl IntoResponse {
    if let Some(error) = params.error {
        let error_url = format!("{}?error={}", state.frontend_url, error);
        return Redirect::temporary(&error_url).into_response();
    }

    let code = match params.code {
        Some(code) => code,
        None => {
            let error_url = format!("{}?error=no_code", state.frontend_url);
            return Redirect::temporary(&error_url).into_response();
        }
    };

    let token_response = match exchange_code_for_token(&state, &code).await {
        Ok(response) => response,
        Err(_) => {
            let error_url = format!("{}?error=token_exchange_failed", state.frontend_url);
            return Redirect::temporary(&error_url).into_response();
        }
    };

    let user = match get_discord_user(&state, &token_response.access_token).await {
        Ok(user) => user,
        Err(_) => {
            let error_url = format!("{}?error=user_fetch_failed", state.frontend_url);
            return Redirect::temporary(&error_url).into_response();
        }
    };

    let jwt_token = match create_jwt_token(
        &state,
        &user,
        &token_response.access_token,
        &token_response.refresh_token,
    ) {
        Ok(token) => token,
        Err(_) => {
            let error_url = format!("{}?error=jwt_creation_failed", state.frontend_url);
            return Redirect::temporary(&error_url).into_response();
        }
    };

    let success_url = format!("{}?token={}", state.frontend_url, jwt_token);
    Redirect::temporary(&success_url).into_response()
}

pub async fn verify_token(headers: HeaderMap, State(state): State<AuthState>) -> impl IntoResponse {
    let token = match extract_token_from_headers(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "No token provided".to_string(),
                }),
            )
                .into_response();
        }
    };

    let claims = match verify_jwt_token(&state, &token) {
        Ok(claims) => claims,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "Invalid token".to_string(),
                }),
            )
                .into_response();
        }
    };

    let user = match get_discord_user(&state, &claims.access_token).await {
        Ok(user) => user,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "discord_api_error".to_string(),
                    message: "Failed to fetch user data from Discord".to_string(),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(UserInfo {
            id: user.id,
            username: user.username,
            discriminator: user.discriminator,
            avatar: user.avatar,
        }),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn get_user_guilds(
    headers: HeaderMap,
    State(state): State<AuthState>,
) -> impl IntoResponse {
    let token = match extract_token_from_headers(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "No token provided".to_string(),
                }),
            )
                .into_response();
        }
    };

    let claims = match verify_jwt_token(&state, &token) {
        Ok(claims) => claims,
        Err(_e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "Invalid token".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Try stored access token first
    match get_discord_guilds(&state, &claims.access_token).await {
        Ok(guilds) => (
            StatusCode::OK,
            Json(GuildsResponse {
                guilds,
                new_token: None,
            }),
        )
            .into_response(),
        Err(e) => {
            if e.to_string().contains("401") {
                match get_fresh_discord_token(&state, &token).await {
                    Ok((new_access_token, new_jwt_token)) => {
                        match get_discord_guilds(&state, &new_access_token).await {
                            Ok(guilds) => (
                                StatusCode::OK,
                                Json(GuildsResponse {
                                    guilds,
                                    new_token: Some(new_jwt_token),
                                }),
                            )
                                .into_response(),
                            Err(e) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: "guilds_fetch_failed".to_string(),
                                    message: format!(
                                        "Failed to fetch guilds after token refresh: {}",
                                        e
                                    ),
                                }),
                            )
                                .into_response(),
                        }
                    }
                    Err(e) => {
                        if e.to_string().contains("invalid_grant") {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(ErrorResponse {
                                    error: "refresh_token_expired".to_string(),
                                    message: "Your Discord session has expired. Please log in again to continue.".to_string(),
                                }),
                            ).into_response()
                        } else {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(ErrorResponse {
                                    error: "discord_token_expired".to_string(),
                                    message: format!(
                                        "Discord token expired, please re-authenticate: {}",
                                        e
                                    ),
                                }),
                            )
                                .into_response()
                        }
                    }
                }
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "guilds_fetch_failed".to_string(),
                        message: format!("Failed to fetch guilds: {}", e),
                    }),
                )
                    .into_response()
            }
        }
    }
}

pub async fn get_current_user(
    headers: HeaderMap,
    State(state): State<AuthState>,
) -> impl IntoResponse {
    let token = match extract_token_from_headers(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "No token provided".to_string(),
                }),
            )
                .into_response();
        }
    };

    let claims = match verify_jwt_token(&state, &token) {
        Ok(claims) => claims,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "Invalid token".to_string(),
                }),
            )
                .into_response();
        }
    };

    let user = match get_discord_user(&state, &claims.access_token).await {
        Ok(user) => user,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "discord_api_error".to_string(),
                    message: "Failed to fetch user data from Discord".to_string(),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(UserInfo {
            id: user.id,
            username: user.username,
            discriminator: user.discriminator,
            avatar: user.avatar,
        }),
    )
        .into_response()
}

async fn exchange_code_for_token(
    state: &AuthState,
    code: &str,
) -> Result<DiscordTokenResponse, Box<dyn std::error::Error + Send + Sync>> {
    let credentials = format!(
        "{}:{}",
        state.discord_client_id, state.discord_client_secret
    );
    let encoded_credentials = general_purpose::STANDARD.encode(credentials);

    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", code);
    params.insert("redirect_uri", state.discord_redirect_uri.as_str());

    let response = state
        .http_client
        .post("https://discord.com/api/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {}", encoded_credentials))
        .form(&params)
        .send()
        .await?;

    let token_response: DiscordTokenResponse = response.json().await?;
    Ok(token_response)
}

async fn get_fresh_discord_token(
    state: &AuthState,
    token: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let claims = verify_jwt_token(state, token)?;

    let credentials = format!(
        "{}:{}",
        state.discord_client_id, state.discord_client_secret
    );
    let encoded_credentials = general_purpose::STANDARD.encode(credentials);

    let mut params = HashMap::new();
    params.insert("grant_type", "refresh_token");
    params.insert("refresh_token", claims.refresh_token.as_str());

    let response = state
        .http_client
        .post("https://discord.com/api/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {}", encoded_credentials))
        .form(&params)
        .send()
        .await?;

    let status = response.status();

    if status.is_success() {
        let token_response: DiscordTokenResponse = response.json().await?;

        let user = DiscordUser {
            id: claims.sub.clone(),
            username: "".to_string(),
            discriminator: "".to_string(),
            avatar: None,
            email: None,
        };

        let new_jwt = create_jwt_token(
            state,
            &user,
            &token_response.access_token,
            &token_response.refresh_token,
        )?;
        Ok((token_response.access_token, new_jwt))
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(format!("Discord token refresh failed {}: {}", status, error_text).into())
    }
}

async fn get_discord_user(
    state: &AuthState,
    access_token: &str,
) -> Result<DiscordUser, Box<dyn std::error::Error + Send + Sync>> {
    let response = state
        .http_client
        .get("https://discord.com/api/users/@me")
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?;

    if response.status().is_success() {
        let user: DiscordUser = response.json().await?;
        Ok(user)
    } else {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(format!("Discord user fetch failed {}: {}", status, error_text).into())
    }
}

async fn get_discord_guilds(
    state: &AuthState,
    access_token: &str,
) -> Result<Vec<DiscordGuild>, Box<dyn std::error::Error + Send + Sync>> {
    let mut guilds_data: Option<Vec<DiscordGuild>> = None;

    while guilds_data.is_none() {
        let response = state
            .http_client
            .get("https://discord.com/api/users/@me/guilds")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;

        let status = response.status();

        if status == 429 {
            let rate_limit_response: DiscordRateLimitResponse = response.json().await?;
            let retry_after = rate_limit_response.retry_after.unwrap_or(3000);
            sleep(std::time::Duration::from_millis(retry_after)).await;
        } else if status.is_success() {
            let guilds: Vec<DiscordGuild> = response.json().await?;
            guilds_data = Some(guilds);
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Discord API error {}: {}", status, error_text).into());
        }
    }

    Ok(guilds_data.unwrap())
}

fn create_jwt_token(
    state: &AuthState,
    user: &DiscordUser,
    access_token: &str,
    refresh_token: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expires_at = now + Duration::days(7);

    let claims = Claims {
        sub: user.id.clone(),
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
    };

    let header = Header::default();
    let encoding_key = EncodingKey::from_secret(state.jwt_secret.as_ref());

    encode(&header, &claims, &encoding_key)
}

pub fn verify_jwt_token(
    state: &AuthState,
    token: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref());
    let validation = Validation::default();

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    if auth_str.starts_with("Bearer ") {
        Some(auth_str[7..].to_string())
    } else {
        None
    }
}
