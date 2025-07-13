use crate::routes::auth::Claims;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub access_token: String,
}

impl From<Claims> for AuthenticatedUser {
    fn from(claims: Claims) -> Self {
        Self {
            id: claims.sub,
            access_token: claims.access_token,
        }
    }
}
