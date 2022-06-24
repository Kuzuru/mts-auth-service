package runners

import (
	"fmt"
	"net"
	"os"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	"gitlab.com/g6834/team32/auth-service/config"
	"gitlab.com/g6834/team32/auth-service/internal/handlers"
	validation "gitlab.com/g6834/team32/auth-service/pkg/JWTValidationService"
)

// StartGRPC starts a gRPC server for JWTValidationService. It retrieves host and port from environment variables.
func StartGRPC() {
	// Start gRPC server
	log.Info().Msgf("Starting gRPC server on %s:%s\n", os.Getenv("HOST"), os.Getenv("GRPC"))

	grpcAddress := fmt.Sprintf("%s:%s", os.Getenv("HOST"), os.Getenv("GRPC"))

	if err := config.Init(); err != nil {
		sentry.CaptureException(err)
		log.Fatal().Err(err)
	}

	// Starting gRPC server
	listener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		sentry.CaptureException(err)
		log.Fatal().Stack().Err(err)
	}

	// Creating new gRPC server handler
	s := grpc.NewServer()
	gRPCServer := &handlers.GRPCServer{}

	validation.RegisterJWTValidationServiceServer(s, gRPCServer)

	if err := s.Serve(listener); err != nil {
		sentry.CaptureException(err)
		log.Fatal().Stack().Err(err)
	}
}
