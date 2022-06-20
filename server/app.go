package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"golang.org/x/crypto/bcrypt"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"

	"main/internal/log"
	ValidateService "main/pkg/JWTValidationService"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"login"`
	Password string `json:"password"`
}

func ParseToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(viper.GetString("token.secret")), nil
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
	signedToken, err := token.SignedString([]byte(viper.GetString("token.secret")))
	if err != nil {
		return "", errors.New("error creating a token")
	}

	return signedToken, nil
}

func Run(port string) {
	// Starting gRPC Client
	cwt, _ := context.WithTimeout(context.Background(), time.Second*5)

	conn, err := grpc.DialContext(cwt, "localhost:4000", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		sentry.CaptureException(err)
		log.Error.Fatal(err)
	}

	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Error.Fatal(err)
		}
	}(conn)

	JWTService := ValidateService.NewJWTValidationServiceClient(conn)
	///////////////////////

	if !fiber.IsChild() {
		log.Info.Printf("Running server on localhost:%s\n", port)
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
		var user User

		if err := c.BodyParser(&user); err != nil {
			c.Status(500)

			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Searching for user in "DB"
		usersList := viper.GetStringMap("users")
		for k := range usersList {
			u := viper.GetStringMapString("users." + k)

			err := bcrypt.CompareHashAndPassword([]byte(u["password"]), []byte(user.Password))

			// If err is nil then we found user with the same name and password
			if err == nil && u["name"] == user.Name {
				// Set correct UID
				user.ID, _ = strconv.Atoi(u["id"])
			}
		}

		// If UID was not set then user is not authorized
		if user.ID == 0 {
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": "Check your username or password",
			})
		}

		// Getting access and refresh tokens expires time
		accessTokenTTL, refreshTokenTTL := viper.GetInt64("token.accessToken.ttl"), viper.GetInt64("token.refreshToken.ttl")

		accessTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Name,
		}, accessTokenTTL)

		if err != nil {
			log.Error.Println(err)
			return c.SendStatus(500)
		}

		refreshTokenString, err := CreateToken(&jwt.MapClaims{
			"id": user.ID,
		}, refreshTokenTTL)

		if err != nil {
			log.Error.Println(err)
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
		validationToken := &ValidateService.IsTokenVaildRequest{Token: c.Cookies("accessToken")}

		_, err := JWTService.IsTokenVaild(context.Background(), validationToken)
		if err != nil {
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
		accessToken := &ValidateService.IsTokenVaildRequest{Token: c.Cookies("accessToken")}
		refreshToken := &ValidateService.IsTokenVaildRequest{Token: c.Cookies("refreshToken")}

		// To make it global outside errnil check
		var accessTokenString string

		_, err := JWTService.IsTokenVaild(context.Background(), accessToken)
		if err != nil {
			// If access token is not valid then we check
			// for refreshToken validity. If refresh token
			// is valid then we creting new access token
			_, err := JWTService.IsTokenVaild(context.Background(), refreshToken)
			if err != nil {
				return c.SendStatus(401)
			}

			// Parsing refresh token to get user id
			refreshTokenClaims, err := ParseToken(c.Cookies("refreshToken"))
			if err != nil {
				return c.SendStatus(500)
			}

			userID := (*refreshTokenClaims)["id"]

			// Searching for user in "DB"
			usersList := viper.GetStringMap("users")
			for k := range usersList {
				user := viper.GetStringMapString("users." + k)

				if user["id"] == fmt.Sprint(userID) {
					// Generating a new pair of tokens
					accessTokenTTL, refreshTokenTTL := viper.GetInt64("token.accessToken.ttl"), viper.GetInt64("token.refreshToken.ttl")

					accessTokenString, err = CreateToken(&jwt.MapClaims{
						"name": user["name"],
					}, accessTokenTTL)

					if err != nil {
						log.Error.Println(err)
						return c.SendStatus(500)
					}

					refreshTokenString, err := CreateToken(&jwt.MapClaims{
						"id": user["id"],
					}, refreshTokenTTL)

					if err != nil {
						log.Error.Println(err)
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
		// access token because it will be setted on
		// the next request
		var accessTokenClaims *jwt.MapClaims

		if err != nil {
			accessTokenClaims, err = ParseToken(accessTokenString)
			if err != nil {
				sentry.CaptureException(err)
				return c.SendStatus(500)
			}
		} else {
			accessTokenClaims, err = ParseToken(c.Cookies("accessToken"))
			if err != nil {
				sentry.CaptureException(err)
				return c.SendStatus(500)
			}
		}

		return c.JSON(fiber.Map{
			"name": (*accessTokenClaims)["name"],
		})
	})

	// Running server in background
	go func() {
		if err := app.Listen(":" + port); err != nil {
			sentry.CaptureException(err)
			log.Error.Panicf("app.Listen: %s", err)
		}
	}()

	// Waiting for quit signal on exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, os.Interrupt)

	<-quit

	_, shutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdown()
}

func CreateToken(claims *jwt.MapClaims, TTL int64) (string, error) {
	token, err := TokenEncode(claims, TTL)

	if err != nil {
		sentry.CaptureException(err)
		return "", err
	}

	return token, nil
}

// SetCookie sets cookie name and value for TTL seconds
func SetCookie(c *fiber.Ctx, name, value string, TTL int64) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    value,
		Expires:  time.Now().Add(time.Second * time.Duration(TTL)).UTC(),
		HTTPOnly: true,
	})
}

// DeleteCookie deletes cookie by name
func DeleteCookie(c *fiber.Ctx, name string) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Unix(0, 0).UTC(),
		HTTPOnly: true,
	})
}

// DeleteAllCookies deletes all cookies
func DeleteAllCookies(c *fiber.Ctx) {
	c.Set("Set-Cookie", "Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly")
}
