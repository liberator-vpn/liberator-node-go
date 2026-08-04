package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path"

	"github.com/TexHik620953/liberator-node-go/internal/utils/cert"
)

func main() {
	const targetDir = "./certs"
	const firstOctet = byte(10)

	_, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	rootCert, err := cert.GenerateRootCA(rootPrivate)
	if err != nil {
		panic(err)
	}

	// Write root
	err = cert.WritePrivateKeyToFile(path.Join(targetDir, "root.key"), rootPrivate)
	if err != nil {
		panic(err)
	}
	err = cert.WriteCertificateToFile(path.Join(targetDir, "root.crt"), rootCert)
	if err != nil {
		panic(err)
	}
	/*
		rootCert, err := cert.ReadCertificateFromFile(path.Join(targetDir, "root.crt"))
		if err != nil {
			panic(err)
		}
		rootPrivate, err := cert.ReadPrivateKeyFromFile(path.Join(targetDir, "root.key"))
		if err != nil {
			panic(err)
		}
	*/
	for i := range 10 {
		childIP := net.IPv4(firstOctet, byte(i+1), 0, 0)
		name := fmt.Sprintf("node_%d", i)

		_, igPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		targetCert, err := cert.IssueNodeCertificate(igPriv, name, rootCert, rootPrivate, childIP)
		if err != nil {
			panic(err)
		}

		err = cert.WritePrivateKeyToFile(path.Join(targetDir, fmt.Sprintf("%s.key", name)), igPriv)
		if err != nil {
			panic(err)
		}
		err = cert.WriteCertificateToFile(path.Join(targetDir, fmt.Sprintf("%s.crt", name)), targetCert)
		if err != nil {
			panic(err)
		}

	}

}
