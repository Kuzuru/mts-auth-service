package internal

import (
	"fmt"
	"github.com/spf13/viper"
)

// User represents clients who are authorized to use the service.
type User struct {
	ID       int    `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

var DbName = viper.GetString("db.name")
var SslMode = viper.GetString("db.sslMode")
var DbHost = viper.GetString("db.host")
var DbPort = viper.GetString("db.port")
var DbUser = viper.GetString("db.postgres_user")
var DbPassword = viper.GetString("db.postgres_password")

var DbInfo = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
	DbHost, DbPort, DbUser, DbPassword, DbName, SslMode)
