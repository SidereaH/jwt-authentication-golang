package auth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("supersecretkey")
var refreshTokenKey = []byte("supersecretrefreshkey") // Новый ключ для токена обновления

type JWTClaim struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

func GenerateJWT(email string, username string) (tokenString string, refreshTokenString string, err error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &JWTClaim{
		Email:    email,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtKey)

	// Генерация токена обновления
	refreshExpirationTime := time.Now().Add(24 * time.Hour) // Токен обновления действителен 24 часа
	refreshClaims := &JWTClaim{
		Email:    email,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshExpirationTime.Unix(),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err = refreshToken.SignedString(refreshTokenKey)

	return
}

func ValidateToken(signedToken string) (err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		},
	)

	if err != nil {
		return
	}

	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		err = errors.New("couldn't parse claims")
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = errors.New("token expired")
		return
	}

	return

}

func GenerateRefreshToken(email string, username string) (refreshTokenString string, err error) {

	expirationTime := time.Now().Add(24 * time.Hour) // Токен обновления действителен 24 часа

	claims := &JWTClaim{

		Email: email,

		Username: username,

		StandardClaims: jwt.StandardClaims{

			ExpiresAt: expirationTime.Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshTokenString, err = refreshToken.SignedString(refreshTokenKey) // Подписываем токен обновления

	return

}

func ValidateRefreshToken(signedToken string) (err error) {

	token, err := jwt.ParseWithClaims(

		signedToken,

		&JWTClaim{},

		func(token *jwt.Token) (interface{}, error) {
			return []byte(refreshTokenKey), nil // Используем ключ для токена обновления

		},
	)

	if err != nil {

		return
	}

	claims, ok := token.Claims.(*JWTClaim)
	if !ok {

		err = errors.New("couldn't parse claims")
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {

		err = errors.New("refresh token expired")

		return

	}

	return
}

func GetClaimsFromRefreshToken(signedToken string) (*JWTClaim, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(refreshTokenKey), nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		return nil, errors.New("couldn't parse claims")
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("refresh token expired")
	}

	return claims, nil
}
