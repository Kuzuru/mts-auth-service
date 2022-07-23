package db

import (
	"database/sql"
	"io/ioutil"

	_ "github.com/lib/pq"

	"gitlab.com/g6834/team32/auth-service/internal"
)

func InitDb() error {
	db, err := sql.Open("postgres", internal.DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`CREATE DATABASE ` + internal.DbName)
	if err != nil {
		return err
	}

	return nil
}

func CreateTables() error {
	db, err := sql.Open("postgres", internal.DbInfo)
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
