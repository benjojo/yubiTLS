package main

import (
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prep/gpg/agent"
)

func main() {
	csrgen := flag.Bool("signcsr", false, "set to try to output a CSR")
	selectedkeyid := flag.String("keyid", "", "the Key ID in the agent to use")
	certpath := flag.String("crtpath", "", "the ssl certificate path")
	cacertpath := flag.String("cacrtpath", "", "the ssl CA certificate path")
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

	cacertbytes, err := ioutil.ReadFile(*cacertpath)

	if err != nil {
		log.Fatalf("Unable to read ca cert %s", err.Error())
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
	var cert tls.Certificate
	var skippedBlockTypes []string

	var certDERBlock *pem.Block
	certDERBlock, _ = pem.Decode(certbytes)

	if certDERBlock.Type == "CERTIFICATE" {
		cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
	} else {
		skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
	}

	certDERBlock, _ = pem.Decode(cacertbytes)

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

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConfig,
		Handler:      http.DefaultServeMux,
		Addr:         "[::]:8443",
	}

	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.Write(
			[]byte("Secure hello from a YubiKey or GPG Smartcard!"))
	})

	log.Printf("Listening")
	log.Println(srv.ListenAndServeTLS("", ""))

	conn.Close()
}

func printKeysAndFail(keys []agent.Key) {
	fmt.Printf("You appear to have not selected a key to use, or the key you selected\n")
	fmt.Printf("Does not exist in the agent at this time, Do you see your key in this list?\n")

	for _, v := range keys {
		log.Printf("Key: %s - %+v\n", v.Keygrip, v)
	}

	os.Exit(1)
}
