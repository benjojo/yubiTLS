package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/prep/gpg/agent"
)

var csrCN = flag.String("csr.cn", "yubitls.benjojo.co.uk", "the Common Name of the CSR you want to generate")

func GenerateCSR(inkey agent.Key) {

	pub := inkey.Public()

	var csrTemplate = x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: *csrCN},
		DNSNames:           []string{*csrCN},
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          pub,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, inkey)
	if err != nil {
		log.Fatal(err)
	}

	pemEncode := func(b []byte, t string) []byte {
		return pem.EncodeToMemory(&pem.Block{Bytes: b, Type: t})
	}

	csrPEM := pemEncode(csrDER, "CERTIFICATE REQUEST")

	if err := ioutil.WriteFile(fmt.Sprintf("%s.csr", *csrCN), csrPEM, 0644); err != nil {
		log.Fatal(err)
	}
}
