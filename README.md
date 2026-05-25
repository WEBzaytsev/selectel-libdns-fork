# Selectel DNS v2 for [libdns](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/selectel)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for the [Selectel DNS v2 API](https://developers.selectel.ru/docs/cloud-services/dns_api/dns_api_actual/), allowing you to manage DNS records in Selectel-hosted zones from any libdns-compatible tool.

## Authorization

The provider authenticates against the Selectel Keystone identity service using a service-user login. See the [Selectel authorization documentation](https://developers.selectel.ru/docs/control-panel/authorization/#%D1%82%D0%BE%D0%BA%D0%B5%D0%BD-keystone) for how to create the required credentials.

The following fields on `Provider` are required:

| Field         | Description                            |
| ------------- | -------------------------------------- |
| `User`        | Selectel service-user login.           |
| `Password`    | Selectel service-user password.        |
| `AccountId`   | Selectel account ID (domain name).     |
| `ProjectName` | Selectel project name owning the zone. |

## Optional features

| Field                           | Description                                                                                                                              |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `EnableDebugLogging`            | Emit verbose DEBUG-level messages on `OperationLogger`. When `OperationLogger` is nil, a logger writing to `os.Stderr` is created automatically. |
| `OperationLogger`               | A `*log.Logger` that receives INFO, ERROR, and (when enabled) DEBUG messages from the provider.                                          |
| `HTTPRequestRetryConfiguration` | Controls retry behaviour for transient HTTP failures (timeouts, 429, 5xx). A zero-value configuration enables sensible defaults.         |

## Behaviour notes

- The Selectel API rejects TTL values below 60. Records submitted with `TTL == 0` are silently clamped to 60 seconds.
- `AppendRecords` automatically falls back to an in-place update when the API reports a 409 Conflict for a record that already exists.
- Transient HTTP failures (timeouts, 429, 500, 502, 503, 504) are retried with exponential backoff. The default policy is 3 retries between 1s and 30s with a multiplier of 2.

## Example

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/libdns/selectel"
)

func main() {
	provider := selectel.Provider{
		User:        os.Getenv("SELECTEL_USER"),
		Password:    os.Getenv("SELECTEL_PASSWORD"),
		AccountId:   os.Getenv("SELECTEL_ACCOUNT_ID"),
		ProjectName: os.Getenv("SELECTEL_PROJECT_NAME"),
	}
	zone := os.Getenv("SELECTEL_ZONE")

	records, err := provider.GetRecords(context.Background(), zone)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	fmt.Println(records)
}
```

See also: [provider_test.go](https://github.com/libdns/selectel/blob/master/provider_test.go)

Always yours [@jjazzme](https://github.com/jjazzme)
