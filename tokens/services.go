package tokens

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ServerKey contextKey = "server"
)

type ServiceClaims struct {
	jwt.RegisteredClaims
	//UserID           uuid.UUID  `json:"sub,omitempty"`
	//UserSession      uuid.UUID  `json:"session_id,omitempty"`
	//UserSubscription uuid.UUID  `json:"subscription_type,omitempty"`
	//UserRole         roles.Role `json:"role"`
	//UserVerified     bool       `json:"verified,omitempty"`
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
	Issuer   string   `json:"iss,omitempty"` //Service issuer
	Subject  string   `json:"sub,omitempty"` //Subject of the JWT, typically the service name (often coincides with the issuer)
	Audience []string `json:"aud,omitempty"` //Audience of the JWT, typically the service that will consume it
	//UserID           uuid.UUID     `json:"user_id,omitempty"`
	//UserSession      uuid.UUID     `json:"session_id,omitempty"`
	//UserSubscription uuid.UUID     `json:"subscription_type,omitempty"`
	//UserRole         roles.Role    `json:"role,omitempty"`
	//UserVerified     bool          `json:"verified,omitempty"`
	Ttl time.Duration `json:"ttl,omitempty"`
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

		//UserID:           request.UserID,
		//UserSession:      request.UserSession,
		//UserSubscription: request.UserSubscription,
		//UserRole:         request.UserRole,
		//UserVerified:     request.UserVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}
