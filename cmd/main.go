package main

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"

	"auth-service/config"
	"auth-service/internal/log"
	"auth-service/internal/runners"
	"auth-service/server"
)

func main() {
	if err := config.Init(); err != nil {
		log.Error.Fatalf("%s", err.Error())
	}

	// Set threads
	config.Runtime()

	// If debug mode is off then shutdown os.Stdout
	if !viper.GetBool("debug") {
		os.Stdout = nil
	}

	// Init sentry
	err := sentry.Init(sentry.ClientOptions{
		Dsn: viper.GetString("sentry.dsn"),
	})

	if err != nil {
		log.Error.Fatalf("sentry.Init: %s", err)
	}

	// Flush buffered events before the program terminates.
	defer sentry.Flush(2 * time.Second)

	// Starting gRPC server only once
	if !fiber.IsChild() {
		go runners.StartGRPC()
	}

	// Start Fiber server
	server.Run(viper.GetString("ports.http"))
}
