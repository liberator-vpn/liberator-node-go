package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"liberator-node-go/internal/appconfig"
	"liberator-node-go/internal/utils/liberatorjwt"
	"liberator-node-go/pkg/ingress"
	"liberator-node-go/pkg/mesh"

	"math/big"
	"time"

	"github.com/google/uuid"
)

func createNode(ctx context.Context, rootCert *x509.Certificate, priv_key []byte, bootstrap []string) *mesh.MeshNode {
	_, n1Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	n1Cert, err := IssueNodeCertificate(n1Priv, "node", rootCert, priv_key)
	if err != nil {
		panic(err)
	}

	node1, err := mesh.New(ctx, &mesh.MeshConfig{
		ListenAddr:     ":0",
		BootstrapNodes: bootstrap,
	}, n1Cert, rootCert)
	if err != nil {
		panic(err)
	}

	return node1
}

func main() {
	cfg, err := appconfig.LoadAppConfig("./config.yaml")
	if err != nil {
		panic(err)
	}

	fmt.Println(cfg)

	ctx := context.Background()

	jwtSecret := []byte("sraka")

	_, priv_key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	rootCert, err := GenerateRootCA(priv_key)
	if err != nil {
		panic(err)
	}

	// Start ingress
	_, igPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ingressCert, err := IssueNodeCertificate(igPriv, "ingress", rootCert, priv_key)
	if err != nil {
		panic(err)
	}
	ig, err := ingress.New(ctx, ":2100", jwtSecret, ingressCert)
	if err != nil {
		panic(err)
	}
	go ig.Run()

	token, err := liberatorjwt.SignToken(uuid.MustParse("a784a74d-ce92-4648-865f-2bd02a4d07ce"), jwtSecret)
	if err != nil {
		panic(err)
	}
	fmt.Println("Original Token: ", token, "\n")

	for range 5 {
		token, err := liberatorjwt.SignToken(uuid.New(), jwtSecret)
		if err != nil {
			panic(err)
		}
		fmt.Println("New Token: ", token, "\n")
	}

	select {}
}

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
) (*tls.Certificate, error) {
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

	// Возвращаем готовую структуру для tls.Config
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  nodePrivKey,
	}, nil
}
