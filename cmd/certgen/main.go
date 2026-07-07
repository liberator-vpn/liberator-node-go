package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"liberator-node-go/internal/utils/cert"
	"path"
)

func main() {
	const targetDir = "./certs"

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

	for i := range 10 {
		name := fmt.Sprintf("node_%d", i)

		_, igPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		targetCert, err := cert.IssueNodeCertificate(igPriv, name, rootCert, rootPrivate)
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
