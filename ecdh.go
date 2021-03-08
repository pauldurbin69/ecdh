package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

const (
	pemBlockPrivate = "EC PRIVATE KEY"
	pemBlockPublic  = "PUBLIC KEY"
	pemCipher       = x509.PEMCipherAES256
)

// GenerateEcdhKey generate an ecdh key pair
func GenerateEcdhKey() (*ecdsa.PrivateKey, error) {

	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SaveEcdhKeyToFile write ecdh key as encrypted PEM file
func SaveEcdhKeyToFile(privateKey *ecdsa.PrivateKey, passPhrase []byte, path string) error {

	encPrivBytes, err := EncodeEcPrivateKey(privateKey, passPhrase)

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, encPrivBytes, 0600)

	return err
}

// ReadEcdhKeyFromFile read encrypted PEM from file
func ReadEcdhKeyFromFile(passPhrase []byte, path string) (*ecdsa.PrivateKey, error) {

	encPriv, err := ioutil.ReadFile(path)

	privateKey, err := DecodeEcPrivateKey(encPriv, passPhrase)

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GenerateSharedKey create shared key from 3rd party public key and local private key
func GenerateSharedKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([32]byte, error) {

	a, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())

	shared := sha256.Sum256(a.Bytes())

	return shared, nil
}

// EncodeEcPrivateKey convert ecdh private key to PEM bytes
// borrowed from https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
func EncodeEcPrivateKey(privateKey *ecdsa.PrivateKey, password []byte) ([]byte, error) {

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	pemEncoded := &pem.Block{Type: pemBlockPrivate, Bytes: x509Encoded}

	pemEncoded, err = x509.EncryptPEMBlock(rand.Reader, pemEncoded.Type, pemEncoded.Bytes, password, pemCipher)

	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(pemEncoded)

	return pemBytes, nil
}

// EncodeEcPrivateKeyToString Encode ecdh private key as PEM string
func EncodeEcPrivateKeyToString(privateKey *ecdsa.PrivateKey, password []byte) (string, error) {

	pemBytes, err := EncodeEcPrivateKey(privateKey, password)
	return string(pemBytes), err
}

// EncodeEcPublicKey encode ecdh public key as PEM bytes
func EncodeEcPublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: pemBlockPublic, Bytes: x509EncodedPub})

	return pemEncodedPub, err
}

// EncodeEcPublicKeyToString encode ecdh public key as PEM string
func EncodeEcPublicKeyToString(publicKey *ecdsa.PublicKey) (string, error) {

	pemEncodedPub, err := EncodeEcPublicKey(publicKey)
	return string(pemEncodedPub), err
}

// DecodeEcPrivateKey convert pem bytes to ecdh private key
func DecodeEcPrivateKey(pemEncodedKey []byte, password []byte) (*ecdsa.PrivateKey, error) {

	var err error
	block, _ := pem.Decode(pemEncodedKey) // discard any trailing text
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing key")
	}
	unencrypted := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == nil {
			return nil, errors.New("PEM is encrypted and password is blank")
		}
		unencrypted, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}
	}
	ecdsaPrivateKey, err := x509.ParseECPrivateKey(unencrypted)
	if err != nil {
		return nil, err
	}

	return ecdsaPrivateKey, nil
}

// DecodeEcPublicKey convert PEM string to ecdh public key
func DecodeEcPublicKey(pemEncodedPub string) *ecdsa.PublicKey {

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return publicKey
}
