package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UsersClaims struct {
	jwt.RegisteredClaims
	Role      string    `json:"role"`
	SessionID uuid.UUID `json:"session_id,omitempty"`
	Verified  bool      `json:"verified,omitempty"`
}

func VerifyUserJWT(ctx context.Context, tokenString, sk string) (UsersClaims, error) {
	claims := UsersClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(sk), nil
	})
	if err != nil || !token.Valid {
		return UsersClaims{}, err
	}
	return claims, nil
}

type GenerateUserJwtRequest struct {
	Issuer   string        `json:"iss,omitempty"`
	Audience []string      `json:"aud,omitempty"`
	User     uuid.UUID     `json:"sub,omitempty"`
	Session  uuid.UUID     `json:"session_id,omitempty"`
	Verified bool          `json:"verified,omitempty"`
	Role     string        `json:"i,omitempty"`
	Ttl      time.Duration `json:"ttl,omitempty"`
}

func GenerateUserJWT(
	request GenerateUserJwtRequest,
	sk string,
) (string, error) {
	expirationTime := time.Now().UTC().Add(request.Ttl * time.Second)
	claims := &UsersClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    request.Issuer,
			Subject:   request.User.String(),
			Audience:  jwt.ClaimStrings(request.Audience),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		SessionID: request.Session,
		Verified:  request.Verified,
		Role:      request.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}

type UserData struct {
	ID        uuid.UUID
	SessionID uuid.UUID
	Verified  bool
	Role      string
}
