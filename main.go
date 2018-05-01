package main

import (
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prep/gpg/agent"
)

func main() {
	csrgen := flag.Bool("signcsr", false, "set to try to poop out a CSR")
	selectedkeyid := flag.String("keyid", "", "the Key ID in the agent to use")
	certpath := flag.String("crtpath", "", "the ssl certificate path")
	flag.Parse()

	options := []string{
		"allow-pinentry-notify",
		"agent-awareness=2.1.0",
	}

	conn, err := agent.Dial("/run/user/1000/gnupg/S.gpg-agent", options)

	if err != nil {
		log.Fatalf("Unable to connect to GPG agent! %s", err.Error())
	}

	key, err := conn.Key(*selectedkeyid)

	if *selectedkeyid == "" || err != nil {
		keys, err := conn.Keys()
		if err != nil {
			log.Fatalf("Unable to read keys from GPG agent! %s", err.Error())
		}

		printKeysAndFail(keys)
	}

	if *csrgen {
		GenerateCSR(key)
		os.Exit(0)
	}

	// We are now going to a TLS server I guess

	if *certpath == "" {
		log.Fatalf("please provide a cert with -crtpath")
	}

	certbytes, err := ioutil.ReadFile(*certpath)

	if err != nil {
		log.Fatalf("Unable to read cert %s", err.Error())
	}

	tlsConfig := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	// config.Certificates[0] = tls.Certificate{}

	// tlsConfig.Certificates[0], err = tls.X509KeyPair(certbytes, []byte(dummykey))
	var cert tls.Certificate
	var skippedBlockTypes []string

	var certDERBlock *pem.Block
	certDERBlock, _ = pem.Decode(certbytes)

	if certDERBlock.Type == "CERTIFICATE" {
		cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
	} else {
		skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
	}
	cert.PrivateKey = key

	tlsConfig.Certificates[0] = cert

	// Apparently this works??

	if err != nil {
		panic(err)
	}

	// mildHack := YubiToTLS{
	// 	k: key,
	// }

	log.Printf("%+v", tlsConfig)

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConfig,
		Handler:      http.DefaultServeMux,
		Addr:         "[::]:8443",
	}

	log.Printf("IN.")
	log.Println(srv.ListenAndServeTLS("", ""))

	conn.Close()
}

type YubiToTLS struct {
	k agent.Key
}

func (y *YubiToTLS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return y.k.Sign(rand, digest, opts)
}

func (y *YubiToTLS) Public() crypto.PublicKey {
	return y.k.Public()
}

func printKeysAndFail(keys []agent.Key) {
	fmt.Printf("You appear to have not selected a key to use, or the key you selected\n")
	fmt.Printf("Does not exist in the agent at this time, Do you see your key in this list?\n")

	for _, v := range keys {
		log.Printf("Key: %s - %+v\n", v.Keygrip, v)
	}

	os.Exit(1)
}
