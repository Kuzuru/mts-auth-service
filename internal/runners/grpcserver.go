package runners

import (
	"net"

	"google.golang.org/grpc"

	"github.com/getsentry/sentry-go"
	"github.com/spf13/viper"

	"auth-service/config"
	"auth-service/internal/handlers"
	"auth-service/internal/log"
	ValidateService "auth-service/pkg/JWTValidationService"
)

func StartGRPC() {
	// Start gRPC server
	log.Info.Printf("Starting gRPC server on port: %s\n", "localhost:4000")

	if err := config.Init(); err != nil {
		sentry.CaptureException(err)
		log.Error.Fatalf("%s", err.Error())
	}

	// Starting gRPC server
	lis, err := net.Listen("tcp", "localhost:"+viper.GetString("ports.grpc"))
	if err != nil {
		sentry.CaptureException(err)
		log.Error.Fatal(err)
	}

	// Creating new gRPC server handler
	s := grpc.NewServer()
	gRPCServer := &handlers.GRPCServer{}

	ValidateService.RegisterJWTValidationServiceServer(s, gRPCServer)

	if err := s.Serve(lis); err != nil {
		sentry.CaptureException(err)
		log.Error.Fatal(err)
	}
}
