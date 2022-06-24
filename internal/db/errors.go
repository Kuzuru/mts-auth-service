package db

import "errors"

// ErrUserAlreadyExists indicates that a user with this login already exists.
var ErrUserAlreadyExists = errors.New("user with this login already exists")

// ErrBadCredentials indicates that a user with this login does not exist or that password hashes do not match.
var ErrBadCredentials = errors.New("invalid login or password")
