package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ServiceKey contextKey = "service"
)

type ServiceClaims struct {
	jwt.RegisteredClaims
}

func VerifyServiceJWT(ctx context.Context, tokenString, sk string) (ServiceClaims, error) {
	claims := ServiceClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})

	if err != nil || !token.Valid {
		return ServiceClaims{}, err
	}

	return claims, nil
}

type GenerateServiceJwtRequest struct {
	Issuer   string        `json:"iss,omitempty"` //Service issuer
	Subject  string        `json:"sub,omitempty"` //Subject of the JWT, typically the service name (often coincides with the issuer)
	Audience []string      `json:"aud,omitempty"` //Audience of the JWT, typically the service that will consume it
	Ttl      time.Duration `json:"ttl,omitempty"`
}

func GenerateServiceJWT(
	request GenerateServiceJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().UTC().Add(request.Ttl * time.Second)
	claims := &ServiceClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    request.Issuer,
			Subject:   request.Subject,
			Audience:  jwt.ClaimStrings(request.Audience),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
