package server

// TODO: Needs more refactoring. I have only extracted POST routes to a new file.

import (
	"context"
	"errors"
	"github.com/spf13/viper"
	"strconv"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"

	_ "gitlab.com/g6834/team32/auth-service/docs"

	"gitlab.com/g6834/team32/auth-service/internal"
	"gitlab.com/g6834/team32/auth-service/internal/db"
	"gitlab.com/g6834/team32/auth-service/internal/handlers"
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

		if err := c.BodyParser(&user); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Searching for user in DB
		err := db.GetUser(user)
		if err != nil {
			return c.Status(403).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Getting access and refresh tokens expires time
		accessTokenTTL, _ := strconv.ParseInt(viper.GetString("ACCESS_TTL"), 10, 64)
		refreshTokenTTL, _ := strconv.ParseInt(viper.GetString("REFRESH_TTL"), 10, 64)

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
}

// TODO: We have to pass tokens through swagger somehow
// @Summary Validate
// @Tags Auth
// @Description This route validates tokens and returns user info
// @ID validate
// @Produce json
// @Success 200 {object} handler.ValidateResponse
// @Failure 401,403,500 {object} handler.ErrorResponse
// @Router /auth/v1/i [post]
func Validate(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	v1.Post("/i", func(c *fiber.Ctx) error {
		accessToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}
		refreshToken := &validation.IsTokenValidRequest{Token: c.Cookies("refreshToken")}

		// To make it global outside err nil check
		var accessTokenString string

		// TODO: refactor this part of code. Probably use err.(type) assertion instead of many errors.Is
		_, err := JWTService.IsTokenValid(context.Background(), accessToken)
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
			var user internal.User
			err = db.GetUser(user)
			if err != nil || user.ID != userID.(int) {
				log.Error().Stack().Msg(err.Error())

				return c.SendStatus(403)
			}

			accessTokenTTL, _ := strconv.ParseInt(viper.GetString("ACCESS_TTL"), 10, 64)
			refreshTokenTTL, _ := strconv.ParseInt(viper.GetString("REFRESH_TTL"), 10, 64)

			accessTokenString, err = CreateToken(&jwt.MapClaims{
				"Login": user.Login,
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

			/*usersList := viper.GetStringMap("users")
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
			}*/
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
				"error": "Invalid token",
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
}
