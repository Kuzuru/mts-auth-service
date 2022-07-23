package db

import (
	"database/sql"
	"errors"
	"regexp"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"gitlab.com/g6834/team32/auth-service/internal"
)

// AddUser adds new user to database.
// If user with such login already exists, UserAlreadyExistsError returned. Otherwise, hashed password is generated
// and user inserted into database. If no more errors occurred, nil is returned.
//
// AddUser should only be used within initial configuration. It is not supposed to provide full registration process.
func AddUser(user internal.User) error {
	db, err := sql.Open("postgres", internal.DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	// Check that login satisfies requirements.
	compile, err := regexp.Compile("^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$")
	if err != nil {
		log.Fatal().Stack().Err(err)
		return err
	}
	if !compile.MatchString(user.Login) || len(user.Login) > 25 || len(user.Login) < 5 {
		log.Error().Err(err)
		return ErrInvalidLogin
	}

	// Check if user with this login already exists
	res := db.QueryRow("SELECT * FROM users where login = $1", user.Login)
	err = res.Scan(&user.ID, &user.Login, &user.Password)
	if errors.Is(err, sql.ErrNoRows) {

		// If login is available, compute hashed password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			return err
		}

		// Insert new user into users table
		_, err = db.Exec("INSERT INTO users(login, password) VALUES($1, $2)", user.Login, hashedPassword)
		if err != nil {
			return err
		}

	} else if err == nil {
		return ErrUserAlreadyExists
	} else {
		return err
	}

	return nil
}

// GetUser searches a user in database by login.
// It then uses bcrypt.CompareHashAndPassword() to compare password hashes.
// If user with such login isn't found or hashes do not match, BadCredentialsError is returned. Otherwise, nil is returned.
func GetUser(user internal.User) error {
	db, err := sql.Open("postgres", internal.DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	// Save password that was passed as argument
	stringPassword := user.Password

	// Search user in database by login
	res := db.QueryRow("SELECT * FROM users where login = $1", user.Login)
	err = res.Scan(&user.ID, &user.Login, &user.Password)
	if errors.Is(err, sql.ErrNoRows) {
		// If no such user was found, return ErrBadCredentials.
		return ErrBadCredentials
	} else if err != nil {
		return err
	}

	// Compare hashed password from database with password passed as argument.
	// If they don't match, return ErrBadCredentials.
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(stringPassword)); err != nil {
		return ErrBadCredentials
	}

	return nil
}
