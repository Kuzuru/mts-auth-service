package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"

	"main/internal/log"
	ValidateService "main/pkg/JWTValidationService"
)

type GRPCServer struct {
	ValidateService.UnimplementedJWTValidationServiceServer
}

func ParseToken(tokenString string) (*jwt.Token, error) {
	// If token contains less than 3 parts then this token is not valid
	tokenSplit := strings.Split(tokenString, ".")
	if len(tokenSplit) != 3 {
		return &jwt.Token{Valid: false}, nil
	}

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

	return token, nil
}

// IsTokenVaild checks if the tokenString is valid. If the token passes
// the check, the return value is *jwt.MapClaims of this token
func (s *GRPCServer) IsTokenVaild(_ context.Context, req *ValidateService.IsTokenVaildRequest) (*ValidateService.IsTokenVaildResponse, error) {
	token, err := ParseToken(req.GetToken())
	if err != nil {
		sentry.CaptureException(err)
		log.Error.Println(err)
		return &ValidateService.IsTokenVaildResponse{}, errors.New("error parsing token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !(ok && token.Valid) {
		return &ValidateService.IsTokenVaildResponse{}, errors.New("invalid token")
	}

	if expiresAt, ok := claims["exp"]; ok && int64(expiresAt.(float64)) < time.Now().UTC().Unix() {
		return &ValidateService.IsTokenVaildResponse{}, errors.New("token is expired")
	}

	return &ValidateService.IsTokenVaildResponse{}, nil
}
