package db

import (
	"database/sql"
	"errors"
	"gitlab.com/g6834/team32/auth-service/internal"
	"golang.org/x/crypto/bcrypt"
)

// AddUser adds new user to database.
// If user with such login already exists, UserAlreadyExistsError returned. Otherwise, hashed password is generated
// and user inserted into database. If no more errors occurred, nil is returned.
//
// AddUser should only be used within initial configuration. It is not supposed to provide full registration process.
func AddUser(user internal.User) error {
	db, err := sql.Open("postgres", DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	res := db.QueryRow("SELECT * FROM users where login = $1", user.Login)
	err = res.Scan(&user.ID, &user.Login, &user.Password)
	if errors.Is(err, sql.ErrNoRows) {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
		if err != nil {
			return err
		}

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
	db, err := sql.Open("postgres", DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	stringPassword := user.Password

	res := db.QueryRow("SELECT * FROM users where login = $1", user.Login)
	err = res.Scan(&user.ID, &user.Login, &user.Password)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBadCredentials
	} else if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(stringPassword))
	if err != nil {
		return err
	}

	return nil
}
