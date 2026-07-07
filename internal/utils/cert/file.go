package cert

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// WriteCertificateToFile saves a certificate in PEM format.
func WriteCertificateToFile(filename string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return os.WriteFile(filename, pemData, 0o644)
}

// WritePrivateKeyToFile saves an ed25519 private key in PKCS#8 PEM format.
func WritePrivateKeyToFile(filename string, privKey ed25519.PrivateKey) error {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	return os.WriteFile(filename, pemData, 0o600)
}

// ReadCertificateFromFile reads a PEM file and returns a *x509.Certificate.
func ReadCertificateFromFile(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ReadPrivateKeyFromFile reads a PEM file (PKCS#8) and returns an ed25519.PrivateKey.
func ReadPrivateKeyFromFile(filename string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("PEM block is not a private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ed25519")
	}
	return edKey, nil
}
