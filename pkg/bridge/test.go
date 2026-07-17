package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// getServerPubKey из HEX приватного ключа делает HEX публичный
func getServerPubKey(privKeyHex string) (string, error) {
	// Декодируем HEX в 32 байта
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex private key: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}

	// ВАЖНО: Вычисляем публичный ключ ДО клампирования (по спецификации Curve25519)
	// Импортируйте "golang.org/x/crypto/curve25519"
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", err
	}

	// Возвращаем сразу в HEX
	return hex.EncodeToString(pubBytes), nil
}

// generateKeyPair генерирует пару ключей сразу в HEX
func generateKeyPair() (privKey string, pubKey string, err error) {
	var privBytes [32]byte
	if _, err = rand.Read(privBytes[:]); err != nil {
		return "", "", err
	}

	// Сначала вычисляем публичный ключ из сырых байт
	pubBytes, err := curve25519.X25519(privBytes[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	// Теперь клампируем приватный ключ для хранения/использования
	privBytes[0] &= 248
	privBytes[31] &= 127
	privBytes[31] |= 64

	// Возвращаем оба ключа в HEX формате
	return hex.EncodeToString(privBytes[:]), hex.EncodeToString(pubBytes), nil
}
