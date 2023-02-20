# gcert
Golang module to generate a self-signed X.509 certificate

Modified version of:  
[https://go.dev/src/crypto/tls/generate_cert.go](https://go.dev/src/crypto/tls/generate_cert.go)

## Docs
[Documentation](https://pkg.go.dev/github.com/mbrostami/gcert)
## Usage
```
import `github.com/mbrostami/gcert`
```
Then call `Generate` function: 
```
err := gcert.Generate("abc.com", "./", opts...)
```

### Options
- `gcert.WithStartDate`
- `gcert.WithDuration`
- `gcert.WithCA`
- `gcert.WithRSABits`
- `gcert.WithP224`
- `gcert.WithP256`
- `gcert.WithP384`
- `gcert.WithP521`
- `gcert.WithED25519`
