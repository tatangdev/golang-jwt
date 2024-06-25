package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func GenerateECDSAKeyPair() (privateKeyStr, publicKeyStr string, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error(err)
		return
	}
	privateKeyStr, err = EncodePrivateECDSA(privateKey)
	if err != nil {
		log.Error(err)
		return
	}

	publicKey := &privateKey.PublicKey
	publicKeyStr, err = EncodePublicECDSA(publicKey)
	if err != nil {
		log.Error(err)
		return
	}
	return
}

func EncodePrivateECDSA(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

func DecodePrivateECDSA(pemEncoded string) (privateKey *ecdsa.PrivateKey, err error) {
	block, rest := pem.Decode([]byte(pemEncoded))
	if len(rest) != 0 && block == nil {
		err = fmt.Errorf("invalid private_key format")
		log.Error(err)
		return
	}
	x509Encoded := block.Bytes
	privateKey, _ = x509.ParseECPrivateKey(x509Encoded)
	return
}

func EncodePublicECDSA(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

func DecodePublicECDSA(pemEncodedPub string) (pubKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub != nil {
		x509EncodedPub := blockPub.Bytes
		genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
		if err != nil {
			log.Error("haha", err)
			return nil, err
		}
		pubKey = genericPublicKey.(*ecdsa.PublicKey)
		return pubKey, nil
	} else {
		return nil, fmt.Errorf("invalid pubkey")
	}
}
