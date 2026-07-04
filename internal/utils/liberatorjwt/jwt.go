package liberatorjwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type LiberatorClaims struct {
	jwt.RegisteredClaims
}

type LiberatorJWT struct {
	secret []byte
}

func New(secret []byte) *LiberatorJWT {
	return &LiberatorJWT{
		secret: secret,
	}
}

func (j *LiberatorJWT) Verify(token string) (*LiberatorClaims, uuid.UUID, error) {
	parsed, err := jwt.ParseWithClaims(token, &LiberatorClaims{}, func(t *jwt.Token) (any, error) {
		// Проверяем алгоритм подписи
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, uuid.Nil, err
	}

	if !parsed.Valid {
		return nil, uuid.Nil, fmt.Errorf("invalid token")
	}

	claims, ok := parsed.Claims.(*LiberatorClaims)
	if !ok {
		return nil, uuid.Nil, fmt.Errorf("invalid claims")
	}

	// Check that sub is valid uuid
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("invalid sub: %v", err)
	}

	return claims, userID, nil
}

func (j *LiberatorJWT) SignToken(userID uuid.UUID) (string, error) {
	claims := &LiberatorClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "liberator",
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 256)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}
