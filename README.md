YubiTLS
===

![logo](/.github/logo.png)

This is a Golang HTTPS server demo that can be driven from a YubiKey as the key backend
source.

This was made for a post on my blog:

___


You will need a functioning setup for Yubikey + GPG.

Program options:

```
$ ./yubiTLS -h
Usage of ./yubiTLS:
  -cacrtpath string
    	the ssl CA certificate path
  -crtpath string
    	the ssl certificate path
  -csr.cn string
    	the Common Name of the CSR you want to generate (default "yubitls.benjojo.co.uk")
  -keyid string
    	the Key ID in the agent to use
  -signcsr
    	set to try to poop out a CSR
```
