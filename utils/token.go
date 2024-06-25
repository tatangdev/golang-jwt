package utils

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

func GenerateToken(methodEncrypt *jwt.SigningMethodECDSA, privateKeyPEM string, tokenData jwt.MapClaims) (token string, err error) {
	privateKey, err := DecodePrivateECDSA(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	tokenGen := jwt.NewWithClaims(methodEncrypt, tokenData)
	token, err = tokenGen.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %v", err)
	}
	return token, nil
}

func ValidateToken(token string, publicKeyPEM string) (valid bool, claims jwt.MapClaims, err error) {
	if token == "" {
		return false, claims, errors.New("empty token")
	}

	tkn, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodES256 != token.Method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		pubKey, err := DecodePublicECDSA(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key: %v", err)
		}
		return pubKey, nil
	})
	if err != nil {
		return false, claims, fmt.Errorf("failed to parse token: %v", err)
	}

	if claims, ok := tkn.Claims.(jwt.MapClaims); ok && tkn.Valid {
		var exp int64
		switch e := claims["exp"].(type) {
		case string:
			conv, err := strconv.Atoi(e)
			if err != nil {
				log.Error(err)
				break
			}
			exp = int64(conv)
		case float64:
			exp = int64(e)
		}
		if exp < time.Now().Unix() {
			return false, claims, errors.New("expired token")
		}
		return true, claims, nil
	}
	return false, claims, errors.New("invalid token")
}
