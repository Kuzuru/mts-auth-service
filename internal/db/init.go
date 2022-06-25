package db

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"

	_ "github.com/lib/pq"
)

var dbName = os.Getenv("DB_NAME")
var sslMode = os.Getenv("SSL_MODE")
var dbUser = os.Getenv("DB_USER")
var dbPassword = os.Getenv("DB_PASSWORD")

var dbInfo = fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s", dbUser, dbPassword, dbName, sslMode)

func InitDb() error {
	db, err := sql.Open("postgres", dbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`CREATE DATABASE ` + dbName)
	if err != nil {
		return err
	}

	return nil
}

func CreateTables() error {
	db, err := sql.Open("postgres", dbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	file, err := ioutil.ReadFile("init.sql")
	if err != nil {
		return err
	}

	_, err = db.Exec(string(file))
	if err != nil {
		return err
	}

	return nil
}
