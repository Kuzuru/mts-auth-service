package server

import "errors"

// ErrUnsupportedAuthMethod indicates that an authentication method provided in request header is not supported
var ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")

// ErrIncorrectCredentialsFormat indicates that credentials passed in request header are in wrong format
var ErrIncorrectCredentialsFormat = errors.New("incorrect user credentials format")
