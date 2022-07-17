package handler

type ErrorResponse struct {
	Error string `json:"error"`
}

type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}
