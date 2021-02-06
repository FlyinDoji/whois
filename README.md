# whois
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/FlyinDoji/whois.svg?branch=master)](https://travis-ci.org/FlyinDoji/whois)
[![Go Report Card](https://goreportcard.com/badge/github.com/FlyinDoji/whois)](https://goreportcard.com/report/github.com/FlyinDoji/whois)
[![codecov](https://codecov.io/gh/FlyinDoji/whois/branch/master/graph/badge.svg)](https://codecov.io/gh/FlyinDoji/whois)

go whois client for domain names with support for proxied queries

# Installation
```
go get -u github.com/FlyinDoji/whois
```

# Usage

```go
import (
  "github.com/flyindoji/whois"
)

s, r, e := whois.Whois("verisign.com")
if e == nil {
  fmt.Println("Queried:", s)
  fmt.Println(r)
}


// Through a SOCKS5 proxy with authentication
addr := "address:port"
username := "user"
passwd := "password"

_, r, e := whois.Proxied("verisign.com", addr, whois.ProxyAuth(username, passwd))
if e == nil {
  fmt.Println(r)
}

// No authentication required
addr := "address:port"

_, r, e := whois.Proxied("verisign.com", addr, nil)
if e == nil {
  fmt.Println(r)
}

```

# TODO

1. Write tests for more TLDs
2. Support for IP addresses
3. Support for punycode TLDs
4. Add more generic TLDs
