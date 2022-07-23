package server

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	_ "gitlab.com/g6834/team32/auth-service/docs"
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

		// Check if request header contains Authorization field
		authHeader := c.GetReqHeaders()["Authorization"]
		if authHeader == "" {
			// If no Authorization info was found in header, expect login info in request body as required by v1.0
			if err := c.BodyParser(&user); err != nil {
				log.Debug().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

		} else {
			// If Authorization info was found in header, assume it is v1.1
			authStr := strings.Split(authHeader, " ")

			// Only support Basic authentication
			if authStr[0] != "Basic" {
				log.Debug().Err(ErrUnsupportedAuthMethod).Msg(ErrUnsupportedAuthMethod.Error())
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": ErrUnsupportedAuthMethod.Error(),
				})
			}

			// Decode base64 auth info
			decoded, err := base64.StdEncoding.DecodeString(authStr[1])
			if err != nil {
				sentry.CaptureException(err)
				log.Error().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// Split user credentials
			userCredentials := strings.Split(string(decoded), ":")

			// Check that userCredentials contains only 2 elements (login and password)
			if len(userCredentials) != 2 {
				log.Debug().Err(ErrIncorrectCredentialsFormat).Msg(ErrIncorrectCredentialsFormat.Error())
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": ErrIncorrectCredentialsFormat.Error(),
				})
			}

			user.Login = userCredentials[0]
			user.Password = userCredentials[1]
		}

		// Searching for user in DB
		err := db.GetUser(user)
		if err != nil {
			log.Debug().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Getting access and refresh tokens ttl
		accessTokenTTL, err := strconv.ParseInt(viper.GetString("token.accessToken.ttl"), 10, 64)
		if err != nil {
			sentry.CaptureException(err)
			log.Error().Stack().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		refreshTokenTTL, err := strconv.ParseInt(viper.GetString("token.refreshToken.ttl"), 10, 64)
		if err != nil {
			sentry.CaptureException(err)
			log.Error().Stack().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		accessTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Login,
		}, accessTokenTTL)

		if err != nil {
			sentry.CaptureException(err)
			log.Error().Stack().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		refreshTokenString, err := CreateToken(&jwt.MapClaims{
			"login": user.Login,
		}, refreshTokenTTL)

		if err != nil {
			sentry.CaptureException(err)
			log.Error().Stack().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
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

		// Check access token validity
		_, err := JWTService.IsTokenValid(context.Background(), accessToken)
		if err != nil {
			// if access token is invalid, check refresh token
			log.Debug().Msg("access token is invalid")
			_, err = JWTService.IsTokenValid(context.Background(), refreshToken)

			if err != nil {
				// if refresh token is invalid, validation has failed
				log.Debug().Msg("refresh token is invalid")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// If refresh token is valid, parse it to retrieve user login
			refreshTokenClaims, err := ParseToken(refreshToken.GetToken())
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			var user internal.User

			// Getting access and refresh tokens ttl
			accessTokenTTL, err := strconv.ParseInt(viper.GetString("token.accessToken.ttl"), 10, 64)
			if err != nil {
				sentry.CaptureException(err)
				log.Error().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
			refreshTokenTTL, err := strconv.ParseInt(viper.GetString("token.refreshToken.ttl"), 10, 64)
			if err != nil {
				sentry.CaptureException(err)
				log.Error().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			accessTokenString, err := CreateToken(&jwt.MapClaims{
				"Login": user.Login,
			}, accessTokenTTL)

			if err != nil {
				sentry.CaptureException(err)
				log.Error().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			refreshTokenString, err := CreateToken(&jwt.MapClaims{
				"Login": user.Login,
			}, refreshTokenTTL)

			if err != nil {
				sentry.CaptureException(err)
				log.Error().Stack().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
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
			log.Error().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"Login": (*accessTokenClaims)["login"],
		})
	})
}

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
		accessToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}
		refreshToken := &validation.IsTokenValidRequest{Token: c.Cookies("refreshToken")}

		// Check access token validity
		_, err := JWTService.IsTokenValid(context.Background(), accessToken)
		if err != nil {
			// if access token is invalid, check refresh token
			log.Debug().Msg("access token is invalid")
			_, err = JWTService.IsTokenValid(context.Background(), refreshToken)

			if err != nil {
				// if refresh token is invalid, validation has failed
				log.Debug().Msg("refresh token is invalid")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
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
// @Failure 403,500 {object} handler.ErrorResponse
// @Router /auth/v1/i [get]
func Info(v1 fiber.Router, JWTService validation.JWTValidationServiceClient) {
	v1.Get("/i", func(c *fiber.Ctx) error {
		accessToken := &validation.IsTokenValidRequest{Token: c.Cookies("accessToken")}
		refreshToken := &validation.IsTokenValidRequest{Token: c.Cookies("refreshToken")}

		// Check access token validity
		_, err := JWTService.IsTokenValid(context.Background(), accessToken)
		if err != nil {
			// if access token is invalid, check refresh token
			log.Debug().Msg("access token is invalid")
			_, err = JWTService.IsTokenValid(context.Background(), refreshToken)

			if err != nil {
				// if refresh token is invalid, validation has failed
				log.Debug().Msg("refresh token is invalid")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// If refresh token is valid, parse it to retrieve user login
			refreshTokenClaims, err := ParseToken(refreshToken.GetToken())
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			return c.JSON(fiber.Map{
				"Login": (*refreshTokenClaims)["login"],
			})
		}

		accessTokenClaims, err := ParseToken(refreshToken.GetToken())
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"Login": (*accessTokenClaims)["login"],
		})
	})
}
