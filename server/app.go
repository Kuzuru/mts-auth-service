package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"gitlab.com/g6834/team32/auth-service/internal"
	"gitlab.com/g6834/team32/auth-service/internal/db"
	"gitlab.com/g6834/team32/auth-service/internal/handlers"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"

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

func Run(port string) {
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
	///////////////////////

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
	)

	// /auth
	auth := app.Group("/auth")

	// Middleware for /auth/v1
	v1 := auth.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")
		return c.Next()
	})

	// Declaring routes
	v1.Post("/login", func(c *fiber.Ctx) error {
		var user internal.User

		if err := c.BodyParser(&user); err != nil {
			c.Status(500)

			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Searching for user in DB
		err = db.GetUser(user)
		if err != nil {
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Getting access and refresh tokens expires time
		accessTokenTTL, _ := strconv.ParseInt(os.Getenv("ACCESS_TTL"), 10, 64)
		refreshTokenTTL, _ := strconv.ParseInt(os.Getenv("REFRESH_TTL"), 10, 64)

		accessTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Login,
		}, accessTokenTTL)

		if err != nil {
			log.Error().Err(err)
			return c.SendStatus(500)
		}

		refreshTokenString, err := CreateToken(&jwt.MapClaims{
			"id": user.ID,
		}, refreshTokenTTL)

		if err != nil {
			log.Error().Err(err)
			return c.SendStatus(500)
		}

		// Access token cookie
		SetCookie(c, "accessToken", accessTokenString, accessTokenTTL)

		// Refresh token cookie
		SetCookie(c, "refreshToken", refreshTokenString, refreshTokenTTL)

		// If there's redirect_uri param then sending redirect command
		if redirectURI := c.Query("redirect_uri"); redirectURI != "" {
			return c.Redirect(redirectURI)
		}

		return c.JSON(fiber.Map{
			"accessToken":  accessTokenString,
			"refreshToken": refreshTokenString,
		})
	})

	v1.Post("/logout", func(c *fiber.Ctx) error {
		validationToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}

		_, err = JWTService.IsTokenValid(context.Background(), validationToken)
		if err != nil {
			log.Error().Err(err)
			c.Status(401)

			return c.JSON(fiber.Map{
				"error": "You're not authorized",
			})
		}

		// Removing accessToken cookie
		DeleteCookie(c, "accessToken")

		// Removing refreshToken cookie
		DeleteCookie(c, "refreshToken")

		// If there's redirect_uri param then sending redirect command
		if redirectURI := c.Query("redirect_uri"); redirectURI != "" {
			return c.Redirect(redirectURI)
		}

		return c.SendStatus(200)
	})

	v1.Post("/i", func(c *fiber.Ctx) error {
		accessToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}
		refreshToken := &validation.IsTokenValidRequest{Token: c.Cookies("refreshToken")}

		// To make it global outside err nil check
		var accessTokenString string

		_, err = JWTService.IsTokenValid(context.Background(), accessToken)
		fmt.Println(err)
		if errors.Is(err, handlers.ErrParseToken) {
			log.Error().Stack().Msg(err.Error())

			return c.SendStatus(500)

		} else if errors.Is(err, handlers.ErrInvalidToken) || errors.Is(err, handlers.ErrExpiredToken) {
			// If access token is not valid then we check
			// for refreshToken validity. If refresh token
			// is valid then we're creating new access token
			_, err = JWTService.IsTokenValid(context.Background(), refreshToken)
			if errors.Is(err, handlers.ErrParseToken) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(500)
			} else if errors.Is(err, handlers.ErrInvalidToken) || errors.Is(err, handlers.ErrExpiredToken) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(403)
			}

			// Parsing refresh token to get user id
			refreshTokenClaims, err := ParseToken(c.Cookies("refreshToken"))
			fmt.Println(err)
			if errors.Is(err, handlers.ErrParseToken) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(500)
			} else if errors.Is(err, handlers.ErrExpiredToken) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(403)
			} else if errors.Is(err, handlers.ErrInvalidToken) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(401)
			}
			userID := (*refreshTokenClaims)["id"]

			// Searching for user in "DB"
			usersList := viper.GetStringMap("users")
			for k := range usersList {
				user := viper.GetStringMapString("users." + k)

				if user["id"] == fmt.Sprint(userID) {
					// Generating a new pair of tokens
					accessTokenTTL, _ := strconv.ParseInt(os.Getenv("ACCESS_TTL"), 10, 64)
					refreshTokenTTL, _ := strconv.ParseInt(os.Getenv("REFRESH_TTL"), 10, 64)
					//accessTokenTTL, refreshTokenTTL := viper.GetInt64("token.accessToken.ttl"), viper.GetInt64("token.refreshToken.ttl")

					accessTokenString, err = CreateToken(&jwt.MapClaims{
						"Login": user["login"],
					}, accessTokenTTL)

					if err != nil {
						log.Error().Err(err)
						return c.SendStatus(500)
					}

					refreshTokenString, err := CreateToken(&jwt.MapClaims{
						"id": user["id"],
					}, refreshTokenTTL)

					if err != nil {
						log.Error().Err(err)
						return c.SendStatus(500)
					}

					// Access token cookie
					SetCookie(c, "accessToken", accessTokenString, accessTokenTTL)

					// Refresh token cookie
					SetCookie(c, "refreshToken", refreshTokenString, refreshTokenTTL)
				}
			}
		}

		// If error was not nil, then we created a new
		// pair of tokens, so we can't use cookie set
		// access token because it will be set on
		// the next request
		var accessTokenClaims *jwt.MapClaims

		accessTokenClaims, err = ParseToken(c.Cookies("accessToken"))
		fmt.Println(err)
		if err != nil {
			sentry.CaptureException(err)
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": "incorrect or no token",
			})
		}

		/*if err != nil {
			accessTokenClaims, err = ParseToken(accessTokenString)
			if err != nil {
				sentry.CaptureException(err)
				return c.SendStatus(500)
			}
		} else {

		}*/

		log.Info().Msg(c.String())

		err = c.JSON(fiber.Map{
			"Login": (*accessTokenClaims)["login"],
		})

		log.Info().Msg(c.String())

		return err
	})

	// Running server in background
	go func() {
		if err := app.Listen(":" + port); err != nil {
			sentry.CaptureException(err)
			log.Fatal().Stack().AnErr("app.Listen: %s", err)
		}
	}()

	// Waiting for quit signal on exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

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
