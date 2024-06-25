package main

import (
	"encoding/json"
	"fmt"
	"generate-keys/utils"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

func main() {
	privateKey, publicKey, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		logrus.Error("failed to generate ECDSA key pair:", err)
		return
	}
	fmt.Println("Private key:", privateKey)
	fmt.Println("Public key:", publicKey)

	tokenData := jwt.MapClaims{
		"title":       "Test generate token",
		"description": "Also test validate token",
		"exp":         time.Now().Add(time.Minute * time.Duration(5)).Unix(),
	}
	token, err := utils.GenerateToken(jwt.SigningMethodES256, privateKey, tokenData)
	if err != nil {
		logrus.Error("failed to generate JWT token:", err)
		return
	}
	fmt.Println("JWT Token:", token)

	valid, claims, err := utils.ValidateToken(token, publicKey)
	if err != nil {
		logrus.Error("failed to validate JWT token:", err)
		return
	}
	fmt.Println("Token valid:", valid)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		logrus.Error("failed to marshal claims to JSON:", err)
		return
	}
	fmt.Println("Token claims:", string(claimsJSON))
}
