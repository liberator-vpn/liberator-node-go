package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func GenerateRootCA(privKey ed25519.PrivateKey) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour), // Для CA лучше поставить 10 лет
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true, // Обязательно true для корневого CA
		Subject: pkix.Name{
			CommonName: "Liberator Root",
		},
	}

	// Самоподписанный: template используется и как шаблон, и как родитель (parent)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func IssueNodeCertificate(
	nodePrivKey ed25519.PrivateKey, // Приватный ключ самой ноды
	nodeName string, // Имя ноды (например, "node-1.mesh")
	caCert *x509.Certificate, // Сертификат корневого CA из первого метода
	caPrivKey ed25519.PrivateKey, // Приватный ключ корневого CA для подписи
) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour), // Валиден 1 год
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // Это конечный сертификат ноды, не CA
		Subject: pkix.Name{
			CommonName: nodeName,
		},
		// Обязательно заполняем DNSNames, чтобы TLS-клиенты могли проверить
		// соответствие хоста без флага InsecureSkipVerify
		DNSNames: []string{nodeName},
	}

	// Подписываем сертификат ноды ключом CA (передаем caCert как родителя)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, nodePrivKey.Public(), caPrivKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func X509ToTLSCertificate(cert *x509.Certificate, privKey ed25519.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw}, // DER-представление сертификата
		PrivateKey:  privKey,
	}
}
