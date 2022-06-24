package main

import (
	"gitlab.com/g6834/team32/auth-service/config"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"gitlab.com/g6834/team32/auth-service/internal/runners"
	"gitlab.com/g6834/team32/auth-service/server"
)

func main() {
	// Set logger output stream and time format
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC1123})

	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal().Msgf("Error loading .env file: %w", err.Error())
	}
	var sentryDsn = os.Getenv("SENTRY_DSN")
	var mode = os.Getenv("MODE")
	var httpPort = os.Getenv("HTTP")

	// Set app mode
	if mode == "prod" {
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
		// If debug mode is off then shutdown os.Stdout (yet we probably shouldn't do this)
		if err := syscall.Close(syscall.Stdout); err != nil {
			sentry.CaptureException(err)
			log.Fatal().Stack().Err(err)
		}
	} else if mode == "trace" {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	} else if mode == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
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
			Login:    "undefined",
			Password: "abcde",
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
