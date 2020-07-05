package util

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
	"time"
)

func JwtBuildAndSignJSON(userId int) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userId,
	})

	tokenString, _ := token.SignedString(secretKey())

	return tokenString
}

func JwtBuildAndSignJSONAnotherSecret(userId int) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userId,
	})

	tokenString, _ := token.SignedString([]byte("different-password"))

	return tokenString
}

type CustomClaim struct {
	UserId int `json:"user_id"`
	jwt.StandardClaims
}

func JwtBuildAndSignWithStandardClaims(userId int) string {
	claims := CustomClaim{
		userId,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Minute * time.Duration(15)).Unix(),
			Issuer:    "sample-issuer",
			Subject:   "sample-username",
			Audience:  "sample-audience",
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secretKey())

	return tokenString
}

func JwtValidate(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secretKey(), nil
	})

	var userId int
	if token != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var userIdClaim = claims["user_id"]
			fetchedUserId := userIdClaim.(float64)

			userId = int(fetchedUserId)
		}
	}

	return userId, err
}

func secretKey() []byte {
	var secretKeyBytes = []byte(os.Getenv("GO_JWT_SAMPLE_SECRET_KEY"))
	return secretKeyBytes
}
