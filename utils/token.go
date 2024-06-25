package utils

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

func GenerateToken(methodEncrypt *jwt.SigningMethodECDSA, _privateKey string, tokenData jwt.MapClaims) (token string, err error) {
	privateKey, err := DecodePrivateECDSA(_privateKey)
	if err != nil {
		return
	}

	tokenGen := jwt.NewWithClaims(methodEncrypt, tokenData)
	token, err = tokenGen.SignedString(privateKey)
	if err != nil {
		return
	}
	return
}

func ValidateToken(token string, pemEncodedPub string) (valid bool, claims jwt.MapClaims, err error) {
	if token == "" {
		return false, claims, errors.New("empty token")
	}
	tkn, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodES256 != token.Method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		pubKey, err := DecodePublicECDSA(pemEncodedPub)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	})
	if err != nil {
		return
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
