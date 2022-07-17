package internal

// User represents clients who are authorized to use the service.
type User struct {
	ID       int    `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
}
