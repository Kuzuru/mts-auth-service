package handlers

type ErrorResponse struct {
	Error string `json:"error"`
}

type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type LogoutResponse struct {
}

type ValidateResponse struct {
	Login string `json:"login"`
}
