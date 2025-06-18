package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/chains-lab/gatekit/roles"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type contextKey string

const (
	RoleKey         contextKey = "role"
	SubjectIDKey    contextKey = "subject"
	SessionIDKey    contextKey = "session"
	SubscriptionKey contextKey = "subscription"
	VerifiedKey     contextKey = "verified"
)

type UsersClaims struct {
	jwt.RegisteredClaims
	Role         roles.Role `json:"role"`
	Session      uuid.UUID  `json:"session_id,omitempty"`
	Subscription uuid.UUID  `json:"subscription_type,omitempty"`
	Verified     bool       `json:"verified,omitempty"`
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
	Issuer       string        `json:"iss,omitempty"`
	Audience     []string      `json:"aud,omitempty"`
	User         uuid.UUID     `json:"sub,omitempty"`
	Session      uuid.UUID     `json:"session_id,omitempty"`
	Subscription uuid.UUID     `json:"subscription_type,omitempty"`
	Verified     bool          `json:"verified,omitempty"`
	Role         roles.Role    `json:"i,omitempty"`
	Ttl          time.Duration `json:"ttl,omitempty"`
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
		Session:      request.Session,
		Subscription: request.Subscription,
		Verified:     request.Verified,
		Role:         request.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(sk))
}

type UserData struct {
	UserID    uuid.UUID  `json:"user_id,omitempty"`
	SessionID uuid.UUID  `json:"session_id,omitempty"`
	SubTypeID uuid.UUID  `json:"subscription_type,omitempty"`
	Verified  bool       `json:"verified,omitempty"`
	Role      roles.Role `json:"role"`
}

func GetUserTokenData(ctx context.Context) (
	data UserData,
	err error,
) {
	user, ok := ctx.Value(SubjectIDKey).(string)
	if !ok {
		return UserData{}, fmt.Errorf("user not authenticated")
	}
	userID, err := uuid.Parse(user)
	if err != nil {
		return UserData{}, fmt.Errorf("user not authenticated")
	}

	session, ok := ctx.Value(SessionIDKey).(uuid.UUID)
	if !ok {
		return UserData{}, fmt.Errorf("sessions not authenticated")
	}

	role, ok := ctx.Value(RoleKey).(roles.Role)
	if !ok {
		return UserData{}, fmt.Errorf("role not authenticated")
	}

	sub, ok := ctx.Value(SubscriptionKey).(uuid.UUID)
	if !ok {
		return UserData{}, fmt.Errorf("subscription type not authenticated")
	}

	ver, ok := ctx.Value(VerifiedKey).(bool)
	if !ok {
		return UserData{}, fmt.Errorf("verified status not authenticated")
	}

	return UserData{
		UserID:    userID,
		SessionID: session,
		SubTypeID: sub,
		Role:      role,
		Verified:  ver,
	}, nil
}
