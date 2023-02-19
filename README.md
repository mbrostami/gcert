# gcert
Golang module to generate a self-signed X.509 certificate

Modified version of:  
[https://go.dev/src/crypto/tls/generate_cert.go](https://go.dev/src/crypto/tls/generate_cert.go)


## Usage
Import `github.com/mbrostami/gcert`
```go
err := gcert.Generate("abc.com", "./")
if err != nil {
    log.Fatal(err)
} 

```