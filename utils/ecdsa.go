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
		log.Error("failed to generate ECDSA key pair:", err)
		return "", "", err
	}

	privateKeyStr, err = EncodePrivateECDSA(privateKey)
	if err != nil {
		log.Error("failed to encode private key:", err)
		return "", "", err
	}

	publicKey := &privateKey.PublicKey
	publicKeyStr, err = EncodePublicECDSA(publicKey)
	if err != nil {
		log.Error("failed to encode public key:", err)
		return "", "", err
	}

	return privateKeyStr, publicKeyStr, nil
}

func EncodePrivateECDSA(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode ECDSA private key: %v", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

func DecodePrivateECDSA(pemEncoded string) (privateKey *ecdsa.PrivateKey, err error) {
	block, rest := pem.Decode([]byte(pemEncoded))
	if len(rest) != 0 && block == nil {
		err = fmt.Errorf("invalid private key format")
		log.Error(err)
		return nil, err
	}

	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		log.Error("failed to decode ECDSA private key:", err)
		return nil, err
	}

	return privateKey, nil
}

func EncodePublicECDSA(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode ECDSA public key: %v", err)
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

func DecodePublicECDSA(pemEncodedPub string) (pubKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub == nil {
		return nil, fmt.Errorf("invalid public key format")
	}

	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		log.Error("failed to decode ECDSA public key:", err)
		return nil, err
	}

	pubKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid ECDSA public key type")
	}

	return pubKey, nil
}
