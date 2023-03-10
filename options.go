package gcert

import (
	"time"
)

const (
	CurveP224 = "P224"
	CurveP256 = "P256"
	CurveP384 = "P384"
	CurveP521 = "P521"
)

type Option func(*options)

type options struct {
	parentCert   string
	parentKey    string
	certFileName string
	keyFileName  string
	validFrom    string
	validFor     time.Duration
	rsaBits      int
	ecdsaCurve   string
	ed25519Key   bool
	isCA         bool
}

func initOptions() options {
	return options{
		certFileName: "cert.pem",
		keyFileName:  "key.pem",
		validFor:     365 * 24 * time.Hour,
		rsaBits:      2048,
	}
}

// WithKeyFileName the generated key file name (default key.pem)
func WithKeyFileName(keyFileName string) Option {
	return func(o *options) {
		o.keyFileName = keyFileName
	}
}

// WithCertFileName the generated cert file name (default cert.pem)
func WithCertFileName(certFileName string) Option {
	return func(o *options) {
		o.certFileName = certFileName
	}
}

// WithSignByParent signs the generated certificate as parent (path of cert and key file of the signer)
func WithSignByParent(parentCertPath, parentKeyPath string) Option {
	return func(o *options) {
		o.parentCert = parentCertPath
		o.parentKey = parentKeyPath
	}
}

// WithStartDate creation date formatted as Jan 1 15:04:05 2011
func WithStartDate(startDate string) Option {
	return func(o *options) {
		o.validFrom = startDate
	}
}

// WithDuration duration that certificate is valid for
func WithDuration(duration time.Duration) Option {
	return func(o *options) {
		o.validFor = duration
	}
}

// WithCA cert should be its own Certificate Authority
func WithCA() Option {
	return func(o *options) {
		o.isCA = true
	}
}

// WithRSABits size of RSA key to generate. Ignored if --ecdsa-curve is set
func WithRSABits(bits int) Option {
	return func(o *options) {
		o.rsaBits = bits
	}
}

// WithP224 ECDSA P224 curve to use to generate a key
func WithP224() Option {
	return func(o *options) {
		o.ecdsaCurve = CurveP224
	}
}

// WithP256 ECDSA P256 (recommended) curve to use to generate a key
func WithP256() Option {
	return func(o *options) {
		o.ecdsaCurve = CurveP256
	}
}

// WithP384 ECDSA P384 curve to use to generate a key
func WithP384() Option {
	return func(o *options) {
		o.ecdsaCurve = CurveP384
	}
}

// WithP521 ECDSA P521 curve to use to generate a key
func WithP521() Option {
	return func(o *options) {
		o.ecdsaCurve = CurveP521
	}
}

// WithED25519 generate an Ed25519 key
func WithED25519() Option {
	return func(o *options) {
		o.ed25519Key = true
	}
}
