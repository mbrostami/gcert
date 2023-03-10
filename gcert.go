package gcert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs
// 'cert.pem' and 'key.pem' into dest directory and will overwrite existing files.
// host is a comma-separated hostnames and IPs to generate a certificate for
func Generate(host, dest string, opts ...Option) error {
	if len(host) == 0 {
		return fmt.Errorf("missing required host parameter")
	}

	o := initOptions()
	for _, opt := range opts {
		opt(&o)
	}

	var priv any
	var err error
	switch o.ecdsaCurve {
	case "":
		if o.ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, o.rsaBits)
		}
	case CurveP224:
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case CurveP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case CurveP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case CurveP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("unrecognized elliptic curve: %q", o.ecdsaCurve)
	}

	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(o.validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", o.validFrom)
		if err != nil {
			return fmt.Errorf("failed to parse creation date: %v", err)
		}
	}

	notAfter := notBefore.Add(o.validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	var parentCert *x509.Certificate
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if o.isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parentCert = &template
	parentKey := priv
	if len(o.parentCert) > 0 {
		parentCert, err = ParsePemCertFile(o.parentCert)
		if err != nil {
			return err
		}
		parentKey, err = ParsePemKeyFile(o.parentKey)
		if err != nil {
			return err
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, publicKey(priv), parentKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	certOut, err := os.Create(fmt.Sprintf("%s/%s", dest, o.certFileName))
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %v", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert.pem: %v", err)
	}

	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing cert.pem: %v", err)
	}

	keyOut, err := os.OpenFile(fmt.Sprintf("%s/%s", dest, o.keyFileName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %v", err)
	}

	if err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to key.pem: %v", err)
	}

	if err = keyOut.Close(); err != nil {
		return fmt.Errorf("error closing key.pem: %v", err)
	}

	return nil
}

// ParsePemCertFile parses the given pem certificate file
func ParsePemCertFile(path string) (*x509.Certificate, error) {
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	block, _ := pem.Decode(der)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	parentCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER data: %v", err)
	}

	return parentCert, nil
}

// Verify the certificate's signature
func Verify(rootCertPath, certPath, dnsName string) error {
	roots := x509.NewCertPool()
	rootCert, err := ParsePemCertFile(rootCertPath)
	if err != nil {
		return err
	}

	roots.AddCert(rootCert)

	cert, err := ParsePemCertFile(certPath)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		DNSName: dnsName,
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %v", err)
	}

	return nil
}

// ParsePemKeyFile parses the given pem key file
func ParsePemKeyFile(path string) (any, error) {
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	block, _ := pem.Decode(der)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to parse key PEM")
	}

	pkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("failed to parse DER data: %v", err)
	}

	return pkey, nil
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
