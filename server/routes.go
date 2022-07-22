package server

// TODO: Needs more refactoring. I have only extracted POST routes to a new file.

import (
	"context"
	"encoding/base64"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	_ "gitlab.com/g6834/team32/auth-service/docs"
	"strconv"
	"strings"

	"gitlab.com/g6834/team32/auth-service/internal"
	"gitlab.com/g6834/team32/auth-service/internal/db"
	validation "gitlab.com/g6834/team32/auth-service/pkg/JWTValidationService"
)

// @Summary Login
// @Tags Auth
// @Description Login to an account
// @ID login-account
// @Accept json
// @Produce json
// @Param input body handler.LoginRequest true "Account info"
// @Success 200 {object} handler.LoginResponse
// @Failure 403,500 {object} handler.ErrorResponse
// @Router /auth/v1/login [post]
func Login(v1 fiber.Router) {
	v1.Post("/login", func(c *fiber.Ctx) error {
		var user internal.User

		header := c.GetReqHeaders()
		auth := header["Authorization"]
		if auth == "" {
			if err := c.BodyParser(&user); err != nil {
				return c.Status(400).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
		} else {
			authStr := strings.Split(auth, " ")
			decoded, _ := base64.StdEncoding.DecodeString(authStr[1])
			userCreds := strings.Split(string(decoded), ":")
			user.Login = userCreds[0]
			user.Password = userCreds[1]
		}

		// Searching for user in DB
		err := db.GetUser(user)
		if err != nil {
			return c.Status(403).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Getting access and refresh tokens expires time
		accessTokenTTL, _ := strconv.ParseInt(viper.GetString("token.accessToken.ttl"), 10, 64)
		refreshTokenTTL, _ := strconv.ParseInt(viper.GetString("token.refreshToken.ttl"), 10, 64)

		accessTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Login,
		}, accessTokenTTL)

		if err != nil {
			log.Error().Err(err)
			return c.SendStatus(500)
		}

		refreshTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Login,
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
}

// TODO: We have to pass tokens through swagger somehow
// @Summary Validate
// @Tags Auth
// @Description This route validates tokens and returns user info
// @ID validate
// @Produce json
// @Success 200 {object} handler.ValidateResponse
// @Failure 401,403,500 {object} handler.ErrorResponse
// @Router /auth/v1/validate [post]
func Validate(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	v1.Post("/validate", func(c *fiber.Ctx) error {
		accessToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}
		refreshToken := &validation.IsTokenValidRequest{Token: c.Cookies("refreshToken")}

		// To make it global outside err nil check
		var accessTokenString string

		_, err := JWTService.IsTokenValid(context.Background(), accessToken)
		if err != nil {
			_, err = JWTService.IsTokenValid(context.Background(), refreshToken)
			if err != nil {
				log.Error().Msg(err.Error())
				c.Status(403)

				return c.JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// Parsing refresh token to get user id
			refreshTokenClaims, err := ParseToken(refreshToken.GetToken())
			if err != nil {
				log.Error().Msg(err.Error())
				c.Status(403)

				return c.JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			var user internal.User

			accessTokenTTL, _ := strconv.ParseInt(viper.GetString("token.accessToken.ttl"), 10, 64)
			refreshTokenTTL, _ := strconv.ParseInt(viper.GetString("token.refreshToken.ttl"), 10, 64)

			accessTokenString, err = CreateToken(&jwt.MapClaims{
				"Login": user.Login,
			}, accessTokenTTL)

			if err != nil {
				log.Error().Err(err)
				c.Status(500)

				return c.JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			refreshTokenString, err := CreateToken(&jwt.MapClaims{
				"Login": user.Login,
			}, refreshTokenTTL)

			if err != nil {
				log.Error().Err(err)
				c.Status(500)

				return c.JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// Access token cookie
			SetCookie(c, "accessToken", accessTokenString, accessTokenTTL)

			// Refresh token cookie
			SetCookie(c, "refreshToken", refreshTokenString, refreshTokenTTL)

			return c.JSON(fiber.Map{
				"Login": (*refreshTokenClaims)["login"],
			})
		}

		// If error was not nil, then we created a new
		// pair of tokens, so we can't use cookie set
		// access token because it will be set on
		// the next request
		var accessTokenClaims *jwt.MapClaims

		accessTokenClaims, err = ParseToken(c.Cookies("accessToken"))
		if err != nil {
			sentry.CaptureException(err)
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"Login": (*accessTokenClaims)["login"],
		})
	})
}

// TODO: Problem with tokens like in Validate route TODO
// @Summary Logout
// @Tags Auth
// @Description Logout from account
// @ID logout-account
// @Produce json
// @Success 200 {string} ok
// @Failure 401,500 {object} handler.ErrorResponse
// @Router /auth/v1/logout [post]
func Logout(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	v1.Post("/logout", func(c *fiber.Ctx) error {
		validationToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}

		_, err := JWTService.IsTokenValid(context.Background(), validationToken)
		if err != nil {
			log.Error().Msg(err.Error())
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
}

// @Summary Info
// @Tags Auth
// @Description Get login
// @ID info
// @Produce json
// @Success 200 {string} ok
// @Failure 401,500 {object} handler.ErrorResponse
// @Router /auth/v1/i [post]
func Info(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	v1.Get("/i", func(c *fiber.Ctx) error {
		validationToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}

		_, err := JWTService.IsTokenValid(context.Background(), validationToken)
		if err != nil {
			log.Error().Err(err)
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": "You're not authorized",
			})
		}

		var accessTokenClaims *jwt.MapClaims

		accessTokenClaims, err = ParseToken(c.Cookies("accessToken"))
		if err != nil {
			sentry.CaptureException(err)
			c.Status(403)

			return c.JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		return c.JSON(fiber.Map{
			"Login": (*accessTokenClaims)["login"],
		})
	})
}
