package handlers

import (
	"fmt"
)

// TokenError records failed token validation.
type TokenError struct {

	// StatusCode is a value that server will return when this error happens.
	StatusCode int

	// Err is the underlying error.
	Err error
}

func (e TokenError) Error() string {
	return fmt.Sprintf("code %d, %s", e.StatusCode, e.Err)
}

// ErrParseToken indicates that the token cannot be parsed. Returned status code is 500.
var ErrParseToken = TokenError{StatusCode: 500, Err: fmt.Errorf("error parsing token")}

// ErrInvalidToken indicates that the token is invalid. Returned status code is 403.
var ErrInvalidToken = TokenError{StatusCode: 403, Err: fmt.Errorf("invalid token")}

// ErrExpiredToken indicates that the token has expired. Returned status code is 403.
var ErrExpiredToken = TokenError{StatusCode: 403, Err: fmt.Errorf("token has expired")}

// ErrIncorrectSigningMethod indicates that the token was signed using incorrect method. Returned status code is 403.
//
// Tokens should be signed with jwt.SigningMethodHMAC.
var ErrIncorrectSigningMethod = TokenError{StatusCode: 403, Err: fmt.Errorf("incorrect signing method")}
