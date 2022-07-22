package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"gitlab.com/g6834/team32/auth-service/config"
	"gitlab.com/g6834/team32/auth-service/internal"
	"gitlab.com/g6834/team32/auth-service/internal/runners"
	"gitlab.com/g6834/team32/auth-service/server"
)

// @title Auth Service API
// @version 2.0
// @contact.name API Support (Discord)
// @contact.url https://discordapp.com/users/258533190652657684
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8626
// @BasePath /
func main() {
	// Set logger output stream and time format
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC1123})

	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal().AnErr("Error loading .env file: %w", err)
	}

	err = config.Init()
	if err != nil {
		log.Fatal().AnErr("Error loading config file: %w", err)
	}

	var sentryDsn = viper.GetString("SENTRY_DSN")
	var mode = viper.GetString("MODE")
	var httpPort = viper.GetString("HTTP")
	internal.DbName = viper.GetString("db.name")
	internal.SslMode = viper.GetString("db.sslMode")
	internal.DbHost = viper.GetString("db.host")
	internal.DbPort = viper.GetString("db.port")
	internal.DbUser = viper.GetString("db.postgres_user")
	internal.DbPassword = viper.GetString("db.postgres_password")

	internal.DbInfo = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		internal.DbHost, internal.DbPort, internal.DbUser, internal.DbPassword, internal.DbName, internal.SslMode)

	// Set app mode
	switch mode {
	case "release":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)

		// If debug mode is off then shutdown os.Stdout (yet we probably shouldn't do this)
		if err := syscall.Close(syscall.Stdout); err != nil {
			sentry.CaptureException(err)
			log.Fatal().Stack().Err(err)
		}

	case "trace":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)

	default:
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	}

	// Load viper config
	// TODO: Decide how different configuration constants will be loaded.
	// This project retrieves configuration constants both from env and viper right now. We need either to choose one of
	// them, or stick to some strategy (e.g. secrets are stored in env and less sensitive data, such as hosts and port
	// numbers are stored in viper).
	err = config.Init()
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	// Set number of processes to runtime.NumCPU
	NumCPU := runtime.GOMAXPROCS(runtime.NumCPU())
	if !fiber.IsChild() {
		log.Info().Msgf("Running with %d CPUs\n", NumCPU)
	}

	// This will add new user with specified login and password. Do not uncomment unless you need to add new user.
	/*if !fiber.IsChild() {
		err = db.AddUser(internal.User{
			Login:    "test123",
			Password: "qwerty",
		})
		if err != nil {
			log.Fatal().Stack().Msg(err.Error())
		}
	}*/

	// Init sentry
	err = sentry.Init(sentry.ClientOptions{
		Dsn:              sentryDsn,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatal().Stack().Msgf("sentry.Init: %s", err)
	}

	defer sentry.Flush(2 * time.Second)

	// Starting gRPC server only once
	if !fiber.IsChild() {
		go runners.StartGRPC()
	}

	// Start Fiber server
	server.Run(httpPort)
}
