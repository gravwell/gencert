# gencert

Static X509 certificate generator as used by [Gravwell](https://gravwell.io) to create self-signed certificates. Unlike openSSL, this makes it very easy to set the Subject Alternative Name in the generated cert.

Although this application may be useful for other purposes, it has not been tested for any use besides generating self-signed certificates for Gravwell webservers.

## usage

* `-host <list>` specifies a comma-separated list of hostnames and/or IP addresses for the Subject Alternative Name fields of the certificate. **Note**: The *last* item specified will be used as the Common Name for the certificate.
* `-duration <duration>` specifies a duration (e.g. '365d') for which the certificate should be valid.
* `-key-file <file>` specifies the name of the file to which the private key file should be written.
* `-cert-file <file>` specifies the name of the file to which the public certificate file should be written.
* `-verbose` enables verbose output.



Based on src/crypto/tls/generate_cert.go from the Go distribution.