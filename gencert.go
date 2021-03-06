// Copyright 2017 Gravwell, Inc. All rights reserved.
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	privHeader string = `PRIV KEY`
	pubHeader  string = `PUB KEY`
)

var (
	host      = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFor  = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	keyFile   = flag.String("key-file", "key.pem", "Key File pem path")
	certFile  = flag.String("cert-file", "cert.pem", "Certificate File pem path")
	doCutKeys = flag.Bool("signing-keys", false, "Generate signing keys instead of SSL certs")
	privFile  = flag.String("priv-file", "private.pem", "Private key path")
	pubFile   = flag.String("pub-file", "public.pem", "Public key path")
	verbose   = flag.Bool("verbose", false, "Verbose output")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Fatalf("Unable to marshal ECDSA private key: %v", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func main() {
	flag.Parse()

	if len(*host) == 0 && !*doCutKeys {
		log.Fatalf("Missing required --host parameter")
	}

	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}

	if *doCutKeys {
		cutKeys()
	} else {
		cutCerts()
	}
}

func cutKeys() {
	//generate a big fucking RSA private public key pair
	privateRsaKey, err := rsa.GenerateKey(rand.Reader, 8192)
	if err != nil {
		log.Fatal(err)
	}

	//generate the PEM file
	privPemKey := &pem.Block{
		Type:  privHeader,
		Bytes: x509.MarshalPKCS1PrivateKey(privateRsaKey),
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(privateRsaKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	pubPemKey := &pem.Block{
		Type:  pubHeader,
		Bytes: pubBytes,
	}

	fout, err := os.Create(*privFile)
	if err != nil {
		log.Fatalf("Failed to open \"%s\": %v\n", *privFile, err)
	}
	if err := pem.Encode(fout, privPemKey); err != nil {
		fout.Close()
		log.Fatalf("Failed to write private PEM block: %v\n", err)
	}
	if err := fout.Close(); err != nil {
		log.Fatalf("Failed to close file handle: %v\n", err)
	}

	fout, err = os.Create(*pubFile)
	if err != nil {
		log.Fatalf("Failed to open public key file \"%s\": %v\n", *pubFile, err)
	}
	if err := pem.Encode(fout, pubPemKey); err != nil {
		log.Fatalf("Failed to write public key file: %v\n", err)
	}
	if err := fout.Close(); err != nil {
		log.Fatalf("Failed to close public key file handle: %v\n", err)
	}
}

func cutCerts() {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gravwell"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,

		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		template.Subject.CommonName = h
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.PermittedDNSDomains = append(template.PermittedDNSDomains, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(*certFile)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", *certFile, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Println("wrote", *certFile)

	keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("failed to open %s for writing: %v", *keyFile, err)
		return
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Println("wrote", *keyFile)
}
