package gcert

import (
	"os"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	type args struct {
		host string
		dest string
		opts []Option
	}
	tests := []struct {
		name          string
		args          args
		wantCert      string
		wantKey       string
		wantSigner    string
		wantErr       bool
		wantVerifyErr bool
	}{
		{
			name: "with no options",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with ED25519",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithED25519(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with P224",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithP224(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with P256",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithP256(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with P384",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithP384(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with P521",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithP521(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with CA",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithCA(),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "cert.pem",
		},
		{
			name: "with startDate",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithStartDate(time.Now().Add(1 * time.Hour).Format("Jan 2 15:04:05 2006")),
				},
			},
			wantCert:      "cert.pem",
			wantKey:       "key.pem",
			wantSigner:    "cert.pem",
			wantVerifyErr: true,
		},
		{
			name: "with expired duration",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithDuration(1 * time.Nanosecond),
				},
			},
			wantCert:      "cert.pem",
			wantKey:       "key.pem",
			wantSigner:    "cert.pem",
			wantVerifyErr: true,
		},
		{
			name: "with valid duration",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithDuration(1 * time.Hour),
				},
			},
			wantCert:      "cert.pem",
			wantKey:       "key.pem",
			wantSigner:    "cert.pem",
			wantVerifyErr: false,
		},
		{
			name: "WithKeyFileName",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithKeyFileName("key_name.pem"),
				},
			},
			wantCert:      "cert.pem",
			wantKey:       "key_name.pem",
			wantSigner:    "cert.pem",
			wantVerifyErr: false,
		},
		{
			name: "WithCertFileName",
			args: args{
				host: "test.example.com",
				dest: "./data",
				opts: []Option{
					WithCertFileName("cert_name.pem"),
				},
			},
			wantCert:      "cert_name.pem",
			wantKey:       "key.pem",
			wantSigner:    "cert_name.pem",
			wantVerifyErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Mkdir("./data", 0750)
			if err := Generate(tt.args.host, tt.args.dest, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}

			_, err := ParsePemCertFile(tt.args.dest + "/" + tt.wantCert)
			if err != nil {
				t.Errorf("ParsePemCertFile() error = %v", err)
			}

			_, err = ParsePemKeyFile(tt.args.dest + "/" + tt.wantKey)
			if err != nil {
				t.Errorf("ParsePemKeyFile() error = %v", err)
			}

			if err = Verify(tt.args.dest+"/"+tt.wantSigner, tt.args.dest+"/"+tt.wantCert, tt.args.host); (err != nil) != tt.wantVerifyErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantVerifyErr)
			}

			os.RemoveAll("./data")
		})
	}
}

func TestGenerateSingByParent(t *testing.T) {
	type args struct {
		host         string
		verifyDomain string
		dest         string
		opts         []Option
	}
	tests := []struct {
		name          string
		args          args
		wantCert      string
		wantKey       string
		wantSigner    string
		wantErr       bool
		wantVerifyErr bool
	}{
		{
			name: "with SingByParent",
			args: args{
				host:         "test.example.com",
				verifyDomain: "test.example.com",
				dest:         "./data",
				opts: []Option{
					WithSignByParent("./data/ca_cert.pem", "./data/ca_key.pem"),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "ca_cert.pem",
		},
		{
			name: "with SingByParent with invalid domain",
			args: args{
				host:         "test.example.com",
				verifyDomain: "example.com",
				dest:         "./data",
				opts: []Option{
					WithSignByParent("./data/ca_cert.pem", "./data/ca_key.pem"),
				},
			},
			wantCert:      "cert.pem",
			wantKey:       "key.pem",
			wantSigner:    "ca_cert.pem",
			wantVerifyErr: true,
		},
		{
			name: "with SingByParent with valid wildcard domain",
			args: args{
				host:         "*.example.com",
				verifyDomain: "abc.example.com",
				dest:         "./data",
				opts: []Option{
					WithSignByParent("./data/ca_cert.pem", "./data/ca_key.pem"),
				},
			},
			wantCert:   "cert.pem",
			wantKey:    "key.pem",
			wantSigner: "ca_cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Mkdir("./data", 0750)
			err := Generate("cadomain.cert", "./data", WithCA(), WithCertFileName("ca_cert.pem"), WithKeyFileName("ca_key.pem"))
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() CA error = %v, wantErr %v", err, tt.wantErr)
			}

			if err = Generate(tt.args.host, tt.args.dest, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}

			_, err = ParsePemCertFile(tt.args.dest + "/" + tt.wantCert)
			if err != nil {
				t.Errorf("ParsePemCertFile() error = %v", err)
			}

			_, err = ParsePemKeyFile(tt.args.dest + "/" + tt.wantKey)
			if err != nil {
				t.Errorf("ParsePemKeyFile() error = %v", err)
			}

			if err = Verify(tt.args.dest+"/"+tt.wantSigner, tt.args.dest+"/"+tt.wantCert, tt.args.verifyDomain); (err != nil) != tt.wantVerifyErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantVerifyErr)
			}

			os.RemoveAll("./data")
		})
	}
}
