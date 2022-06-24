package db

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

var DbInfo = "user=postgres password=qwerty dbname=usersdb sslmode=disable"
var DbName = "usersdb"

func InitDb() error {
	fmt.Print("After init")
	db, err := sql.Open("postgres", DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Print("After con")

	_, err = db.Exec(`CREATE DATABASE ` + DbName)
	if err != nil {
		fmt.Print("After create")
		return err
	}

	return nil
}

func CreateTables() error {
	db, err := sql.Open("postgres", DbInfo)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`create table users(
    	id  serial
        	constraint users_pk
        	primary key,
    	login    varchar(40)  not null,
    	password varchar(256) not null
	);

	create unique index users_id_uindex
    on users (id);

	create unique index users_login_uindex
    on users (login);`)

	if err != nil {
		return err
	}

	return nil
}
