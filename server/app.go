package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2/middleware/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	validation "gitlab.com/g6834/team32/auth-service/pkg/JWTValidationService"
)

func ParseToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(os.Getenv("SECRET")), nil
		},
	)

	if err != nil {
		return nil, errors.New("error parsing token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !(ok && token.Valid) {
		return nil, errors.New("invalid token")
	}

	if expiresAt, ok := claims["exp"]; ok && int64(expiresAt.(float64)) < time.Now().UTC().Unix() {
		return nil, errors.New("token is expired")
	}

	return &claims, nil
}

func TokenEncode(claims *jwt.MapClaims, expiryAfter int64) (string, error) {
	// Setting default expiryAfter
	if expiryAfter == 0 {
		expiryAfter = viper.GetInt64("token.expiry_after")
	}

	// Or we can use time.Now().Add(time.Second * time.Duration(expiryAfter)).UTC().Unix()
	(*claims)["exp"] = time.Now().UTC().Unix() + expiryAfter

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Our signed JWT token string
	signedToken, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", errors.New("error creating a token")
	}

	return signedToken, nil
}

func RegisterHTTPEndpoints(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	Login(v1)

	Logout(v1, JWTService)

	Validate(v1, JWTService)
}

func Run(port string) {
	// TODO: Clean app.go
	// Starting gRPC Client
	cwt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(cwt, "localhost:4000",
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		sentry.CaptureException(err)
		log.Fatal().Stack().Err(err)
	}

	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Fatal().Stack().Err(err)
		}
	}(conn)

	JWTService := validation.NewJWTValidationServiceClient(conn)

	if !fiber.IsChild() {
		log.Info().Msgf("Running server on %s:%s\n", os.Getenv("HOST"), os.Getenv("HTTP"))
	}

	// Declaring app router
	app := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
	})

	// Using middlewares
	app.Use(
		recover.New(),
		logger.New(),
		pprof.New(),
	)

	// /profiler
	debug := app.Group("/debug")

	profiler := debug.Group("/pprof")

	profiler.Post("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// /auth
	auth := app.Group("/auth")

	// Middleware for /auth/v1
	v1 := auth.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")
		return c.Next()
	})

	// Registering endpoints
	RegisterHTTPEndpoints(v1, JWTService)

	// Running server in background
	go func() {
		if err := app.Listen(":" + port); err != nil {
			sentry.CaptureException(err)
			log.Fatal().Stack().AnErr("app.Listen: %s", err)
		}
	}()

	// Waiting for quit signal on exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	<-quit
}

func CreateToken(claims *jwt.MapClaims, TTL int64) (string, error) {
	token, err := TokenEncode(claims, TTL)

	if err != nil {
		sentry.CaptureException(err)
		return "", err
	}

	return token, nil
}

// SetCookie sets cookie login and value for TTL seconds
func SetCookie(c *fiber.Ctx, login, value string, TTL int64) {
	c.Cookie(&fiber.Cookie{
		Name:     login,
		Value:    value,
		Expires:  time.Now().Add(time.Second * time.Duration(TTL)).UTC(),
		HTTPOnly: true,
	})
}

// DeleteCookie deletes cookie by login
func DeleteCookie(c *fiber.Ctx, login string) {
	c.Cookie(&fiber.Cookie{
		Name:     login,
		Value:    "",
		Expires:  time.Unix(0, 0).UTC(),
		HTTPOnly: true,
	})
}
