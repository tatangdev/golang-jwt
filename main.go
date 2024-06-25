package main

import (
	"encoding/json"
	"fmt"

	"generate-keys/utils"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

func main() {
	privateKey, publicKey, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		log.Error(err)
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
		log.Error(err)
		return
	}
	fmt.Println("JWT Token:", token)

	valid, claims, err := utils.ValidateToken(token, publicKey)
	if err != nil {
		log.Error(err)
		return
	}
	fmt.Println("Token valid:", valid)

	b, _ := json.Marshal(claims)
	fmt.Println("Token claims:", string(b))
}
