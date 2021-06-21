package server

type LoginData struct {
	Email    string
	Password string
}

type CreateUserData struct {
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type LogoutData struct {
	AccessToken string `json:"access_token"`
}

type RefreshData struct {
	RefreshToken string `json:"refresh_token"`
}

type ValidateTokenData struct {
	Email        string `json:"email"`
	Token        string `json:"token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type SessionResponseData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Email        string `json:"email"`
	ExpiresAt    int64  `json:"expires_at"`
}
