package handlers

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
