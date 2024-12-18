package controllers

import (
	"jwt-authentication-golang/auth"
	"jwt-authentication-golang/database"
	"jwt-authentication-golang/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

type TokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func GenerateToken(context *gin.Context) {
	var request TokenRequest
	var user models.User
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}

	// check if email exists and password is correct
	record := database.Instance.Where("email = ?", request.Email).First(&user)
	if record.Error != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": record.Error.Error()})
		context.Abort()
		return
	}

	credentialError := user.CheckPassword(request.Password)
	if credentialError != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		context.Abort()
		return
	}

	tokenString, refreshTokenString, err := auth.GenerateJWT(user.Email, user.Username)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	context.JSON(http.StatusOK, gin.H{"token": tokenString, "refresh_token": refreshTokenString})
}

func RefreshToken(context *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}

	if err := auth.ValidateRefreshToken(request.RefreshToken); err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		context.Abort()
		return
	}

	claims := &auth.JWTClaim{}
	if err := auth.ValidateRefreshToken(request.RefreshToken); err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		context.Abort()
		return
	}

	claims, _ = auth.GetClaimsFromRefreshToken(request.RefreshToken)

	tokenString, refreshTokenString, err := auth.GenerateJWT(claims.Email, claims.Username)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	context.JSON(http.StatusOK, gin.H{"token": tokenString, "refresh_token": refreshTokenString})
}
