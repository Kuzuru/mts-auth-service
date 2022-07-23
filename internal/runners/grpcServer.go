package runners

import (
	"context"
	"fmt"
	"github.com/spf13/viper"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	"gitlab.com/g6834/team32/auth-service/internal/handlers"
	validation "gitlab.com/g6834/team32/auth-service/pkg/JWTValidationService"
)

// StartGRPC starts a gRPC server for JWTValidationService. It retrieves host and port from environment variables.
func StartGRPC() {
	// Start gRPC server
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Info().Msgf("Starting gRPC server on %s:%s\n", viper.GetString("HOST"), viper.GetString("GRPC"))

	grpcAddress := fmt.Sprintf("%s:%s", viper.GetString("HOST"), viper.GetString("GRPC"))

	listener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		sentry.CaptureException(err)
		log.Fatal().Stack().Err(err)
	}

	// Creating new gRPC server handlers
	s := grpc.NewServer()
	gRPCServer := &handlers.GRPCServer{}

	validation.RegisterJWTValidationServiceServer(s, gRPCServer)

	// Starting gRPC server
	// This is, almost certainly, not a graceful shutdown. Works just fine, but probably should be rewritten.
	go func() {
		if err = s.Serve(listener); err == nil {
			sentry.CaptureException(err)
			log.Fatal().Stack().Err(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	<-quit
}
