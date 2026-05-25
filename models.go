package selectel

import (
	"time"
)

const (
	cApiBaseUrl               = "https://api.selectel.ru/domains/v2"
	cGetKeystoneTokenTemplate = `{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"{{.User}}","domain":{"name":"{{.AccountId}}"},"password":"{{.Password}}"}}},"scope":{"project":{"name":"{{.ProjectName}}","domain":{"name":"{{.AccountId}}"}}}}}`
	cTokensUrl                = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
	cKeystoneTokenHeader      = "X-Subject-Token"

	// cHTTPClientTimeout bounds every individual HTTP round-trip the
	// provider performs against the Selectel API.
	cHTTPClientTimeout = 30 * time.Second

	// cMinSelectelTTL is the lowest TTL the Selectel API accepts. Any
	// record submitted with a smaller TTL is silently clamped to this
	// value by libdnsToRecord.
	cMinSelectelTTL = 60
)

// HTTPRequestRetryConfiguration controls the exponential-backoff retry
// behaviour of the provider for transient HTTP failures.
//
// A zero-value configuration (the default) is interpreted as "use
// sensible defaults" - see CreateDefaultHTTPRequestRetryConfiguration.
// To run requests without any retries, set MaximumRetryAttempts to 0
// and any other field to a non-zero value (e.g. InitialRetryDelay: 1).
type HTTPRequestRetryConfiguration struct {
	// MaximumRetryAttempts is the number of retry attempts performed
	// after the initial request, so the total number of attempts is
	// MaximumRetryAttempts + 1.
	MaximumRetryAttempts int
	// InitialRetryDelay is the delay before the first retry.
	InitialRetryDelay time.Duration
	// MaximumRetryDelay caps the backoff between retries.
	MaximumRetryDelay time.Duration
	// ExponentialBackoffMultiplier scales the delay on each retry.
	ExponentialBackoffMultiplier float64
}

// CreateDefaultHTTPRequestRetryConfiguration returns a conservative
// retry policy suitable for most callers: up to 3 retries with
// exponential backoff from 1s to a maximum of 30s.
func CreateDefaultHTTPRequestRetryConfiguration() HTTPRequestRetryConfiguration {
	return HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         3,
		InitialRetryDelay:            1 * time.Second,
		MaximumRetryDelay:            30 * time.Second,
		ExponentialBackoffMultiplier: 2.0,
	}
}

var (
	httpMethods = httpMethod{
		post:   "POST",
		get:    "GET",
		patch:  "PATCH",
		delete: "DELETE",
		put:    "PUT",
	}

	recordMethods = recordMethod{
		get:    "GET",
		append: "APPEND",
		set:    "SET",
		delete: "DELETE",
	}
)

type httpMethod struct {
	post   string
	get    string
	patch  string
	delete string
	put    string
}

type recordMethod struct {
	get    string
	append string
	set    string
	delete string
}

// Zones is the API envelope returned by the Selectel /zones endpoint.
type Zones struct {
	Zones []Zone `json:"result"`
}

// Zone is a Selectel DNS zone.
type Zone struct {
	Name string `json:"name"`
	// ID is the Selectel-assigned zone ID.
	ID string `json:"id"`
}

// Recordset is the API envelope returned by the Selectel
// /zones/{id}/rrset endpoint.
type Recordset struct {
	Records []Record `json:"result"`
}

// Record is a single RRset entry in the Selectel API representation.
type Record struct {
	ID      string       `json:"id,omitempty"`
	Type    string       `json:"type"`
	Name    string       `json:"name"`
	Records []RecordItem `json:"records"`
	TTL     int          `json:"ttl"`
}

// RecordItem is a single value within a Selectel RRset.
type RecordItem struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}
