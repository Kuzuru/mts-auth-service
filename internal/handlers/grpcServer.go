package handlers

import (
	"context"
	"github.com/rs/zerolog/log"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"

	ValidateService "gitlab.com/g6834/team32/auth-service/pkg/JWTValidationService"
)

type GRPCServer struct {
	ValidateService.UnimplementedJWTValidationServiceServer
}

// IsTokenValid checks if the tokenString is valid. If the token passes
// the check, the return value is *jwt.MapClaims of this token
func (s *GRPCServer) IsTokenValid(_ context.Context, req *ValidateService.IsTokenValidRequest) (*ValidateService.IsTokenValidResponse, error) {
	tokenString := req.GetToken()
	if len(strings.Split(tokenString, ".")) != 3 {
		return &ValidateService.IsTokenValidResponse{}, ErrInvalidToken
	}

	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrIncorrectSigningMethod
			}

			return []byte(viper.GetString("token.secret")), nil
		},
	)
	if err != nil {
		sentry.CaptureException(err)
		log.Error().Err(err)
		return &ValidateService.IsTokenValidResponse{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return &ValidateService.IsTokenValidResponse{}, ErrInvalidToken
	}

	if expiresAt, ok := claims["exp"]; ok && int64(expiresAt.(float64)) < time.Now().UTC().Unix() {
		return &ValidateService.IsTokenValidResponse{}, ErrExpiredToken
	}

	return &ValidateService.IsTokenValidResponse{}, nil
}
