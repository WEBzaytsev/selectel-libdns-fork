package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"golang.org/x/net/idna"
)

// httpError represents a non-2xx HTTP response from the Selectel API.
// It exposes the status code structurally so callers do not have to
// parse error strings to react to specific HTTP conditions
// (e.g. 409 Conflict during AppendRecords).
type httpError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.Status, e.StatusCode, e.Body)
}

// deserialization unmarshals a JSON payload into a value of type T.
func deserialization[T any](data []byte) (T, error) {
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	return result, nil
}

// urlGenerator builds an absolute API URL from a path template and
// optional positional arguments (substituted via fmt.Sprintf).
func urlGenerator(path string, args ...interface{}) string {
	return fmt.Sprintf(cApiBaseUrl+path, args...)
}

// makeApiRequest issues an authenticated request to the Selectel API
// with retry support for transient failures.
//
//	ctx    - request context
//	method - HTTP method (GET, POST, DELETE, PATCH, PUT)
//	path   - path template (joined with cApiBaseUrl, fed to fmt.Sprintf)
//	body   - optional request body
//	args   - positional substitutions for path
func (p *Provider) makeApiRequest(ctx context.Context, method string, path string, body io.Reader, args ...interface{}) ([]byte, error) {
	return p.executeHTTPRequestWithRetryLogic(ctx, method, path, body, args...)
}

// getZoneID resolves a zone name to its Selectel zone ID, caching the
// result on the provider for subsequent calls.
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	p.writeDebugLogMessage("GET_ZONE_ID", "Looking up zone ID for zone: %s", zone)

	if zoneId := p.ZonesCache[zone]; zoneId != "" {
		p.writeDebugLogMessage("GET_ZONE_ID", "Found zone ID in cache: %s", zoneId)
		return zoneId, nil
	}

	p.writeDebugLogMessage("GET_ZONE_ID", "Zone ID not in cache, fetching from API")

	zonesB, err := p.makeApiRequest(ctx, httpMethods.get, fmt.Sprintf("/zones?filter=%s", url.QueryEscape(zone)), nil)
	if err != nil {
		p.writeErrorLogMessage("GET_ZONE_ID", "Failed to fetch zones from API: %v", err)
		return "", fmt.Errorf("failed to fetch zones: %w", err)
	}

	zones, err := deserialization[Zones](zonesB)
	if err != nil {
		p.writeErrorLogMessage("GET_ZONE_ID", "Failed to deserialize zones response: %v", err)
		return "", fmt.Errorf("failed to deserialize zones: %w", err)
	}

	if len(zones.Zones) == 0 {
		p.writeErrorLogMessage("GET_ZONE_ID", "No zones found for zone: %s", zone)
		return "", fmt.Errorf("no zoneId for zone %s", zone)
	}

	zoneId := zones.Zones[0].ID
	p.writeInfoLogMessage("GET_ZONE_ID", "Found zone ID: %s for zone: %s", zoneId, zone)

	if p.ZonesCache == nil {
		p.ZonesCache = make(map[string]string)
	}
	p.ZonesCache[zone] = zoneId

	return zoneId, nil
}

// recordToLibdns converts a Selectel API Record into the libdns.Record
// representation expected by libdns consumers.
func recordToLibdns(zone string, record Record) libdns.Record {
	ttlDuration := time.Duration(record.TTL) * time.Second

	var dataBuilder strings.Builder
	for i, recVal := range record.Records {
		if i > 0 {
			dataBuilder.WriteString("\n")
		}
		if record.Type == "TXT" {
			dataBuilder.WriteString(strings.ReplaceAll(recVal.Content, "\"", ""))
		} else {
			dataBuilder.WriteString(recVal.Content)
		}
	}

	fqdn := nameNormalizer(record.Name, zone)
	nameRel := libdns.RelativeName(fqdn, zone)

	return libdns.RR{
		Name: nameRel,
		TTL:  ttlDuration,
		Type: record.Type,
		Data: dataBuilder.String(),
	}
}

// mapRecordsToLibds converts a slice of Selectel records into libdns
// records.
func mapRecordsToLibds(zone string, records []Record) []libdns.Record {
	libdnsRecords := make([]libdns.Record, len(records))
	for i, record := range records {
		libdnsRecords[i] = recordToLibdns(zone, record)
	}
	return libdnsRecords
}

// libdnsToRecord converts a libdns.Record into the Selectel API record
// representation. The Selectel API rejects TTL values below 60, so a
// zero TTL is silently promoted to 60.
func libdnsToRecord(zone string, libdnsRecord libdns.Record) Record {
	rr := libdnsRecord.RR()

	ttl := rr.TTL.Seconds()
	if ttl < cMinSelectelTTL {
		ttl = cMinSelectelTTL
	}

	if rr.Data == "" {
		return Record{}
	}

	recVals := strings.Split(rr.Data, "\n")
	valueRV := make([]RecordItem, 0, len(recVals))
	for _, recVal := range recVals {
		recVal = strings.TrimSpace(recVal)
		if recVal == "" {
			continue
		}
		if rr.Type == "TXT" {
			recVal = strings.Trim(recVal, "\"")
			valueRV = append(valueRV, RecordItem{Content: "\"" + recVal + "\"", Disabled: false})
		} else {
			valueRV = append(valueRV, RecordItem{Content: recVal, Disabled: false})
		}
	}

	if len(valueRV) == 0 {
		return Record{}
	}

	fqdn := nameNormalizer(rr.Name, zone)
	rel := libdns.RelativeName(fqdn, zone)

	var apiName string
	if rel == "" || rel == "@" || rel == "." {
		apiName = strings.TrimSuffix(zone, ".")
	} else {
		apiName = strings.TrimSuffix(fqdn, ".")
	}

	return Record{
		Type:    rr.Type,
		Name:    apiName,
		Records: valueRV,
		TTL:     int(ttl),
	}
}

// getSelectelRecords fetches all records of a zone from the Selectel
// API using the zone ID.
func (p *Provider) getSelectelRecords(ctx context.Context, zoneId string) ([]Record, error) {
	p.writeDebugLogMessage("GET_RECORDS", "Fetching records for zone ID: %s", zoneId)

	recordB, err := p.makeApiRequest(ctx, httpMethods.get, "/zones/%s/rrset", nil, zoneId)
	if err != nil {
		p.writeErrorLogMessage("GET_RECORDS", "Failed to fetch records for zone ID %s: %v", zoneId, err)
		return nil, fmt.Errorf("failed to fetch records: %w", err)
	}

	recordset, err := deserialization[Recordset](recordB)
	if err != nil {
		p.writeErrorLogMessage("GET_RECORDS", "Failed to deserialize records response for zone ID %s: %v", zoneId, err)
		return nil, fmt.Errorf("failed to deserialize records: %w", err)
	}

	p.writeInfoLogMessage("GET_RECORDS", "Successfully fetched %d records for zone ID: %s", len(recordset.Records), zoneId)
	return recordset.Records, nil
}

// updateSelectelRecord patches an existing record by its ID.
func (p *Provider) updateSelectelRecord(ctx context.Context, zone string, zoneId string, record Record) (Record, error) {
	p.writeDebugLogMessage("UPDATE_RECORD", "Updating record ID %s for zone %s (zone ID: %s)", record.ID, zone, zoneId)

	body, err := json.Marshal(record)
	if err != nil {
		p.writeErrorLogMessage("UPDATE_RECORD", "Failed to marshal record for update: %v", err)
		return Record{}, fmt.Errorf("failed to marshal record: %w", err)
	}

	p.writeDebugLogMessage("UPDATE_RECORD", "Sending JSON to API: %s", string(body))

	_, err = p.makeApiRequest(ctx, httpMethods.patch, "/zones/%s/rrset/%s", bytes.NewReader(body), zoneId, record.ID)
	if err != nil {
		p.writeErrorLogMessage("UPDATE_RECORD", "Failed to update record ID %s: %v", record.ID, err)
		return Record{}, fmt.Errorf("failed to update record: %w", err)
	}

	p.writeInfoLogMessage("UPDATE_RECORD", "Successfully updated record ID %s for zone %s", record.ID, zone)
	return record, nil
}

// nameNormalizer normalises a record name to a fully qualified domain
// name within the given zone.
//
//	test          => test.zone.
//	test.zone     => test.zone.
//	test.zone.    => test.zone.
//	test.subzone  => test.subzone.zone.
func nameNormalizer(name string, zone string) string {
	name = strings.TrimSpace(name)
	zone = strings.TrimSuffix(zone, ".")

	if name == "@" || name == "" || name == "." {
		return zone + "."
	}

	name = strings.TrimSuffix(name, ".")
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name + "."
	}

	return name + "." + zone + "."
}

// idFromRecordsByLibRecord finds an existing Selectel record whose
// (name, type) pair matches the given libdns record. Comparison is
// case-insensitive and IDN-aware (both sides are converted to ASCII).
func (p *Provider) idFromRecordsByLibRecord(records []Record, libRecord libdns.Record, zone string) (string, bool) {
	rr := libRecord.RR()

	zoneASCII, err := idna.ToASCII(zone)
	if err != nil {
		zoneASCII = zone
	}

	nameNorm := strings.ToLower(strings.TrimSuffix(nameNormalizer(rr.Name, zoneASCII), "."))

	p.writeDebugLogMessage("ID_FROM_RECORDS", "Looking for record: name=%s, type=%s, zone=%s", nameNorm, rr.Type, zoneASCII)

	for _, record := range records {
		recordNameASCII, err := idna.ToASCII(strings.TrimSuffix(record.Name, "."))
		if err != nil {
			recordNameASCII = strings.TrimSuffix(record.Name, ".")
		}

		recordNameNorm := strings.ToLower(strings.TrimSuffix(nameNormalizer(recordNameASCII, zoneASCII), "."))

		if recordNameNorm == nameNorm && rr.Type == record.Type {
			p.writeDebugLogMessage("ID_FROM_RECORDS", "Match found! Returning ID: %s", record.ID)
			return record.ID, true
		}
	}

	p.writeDebugLogMessage("ID_FROM_RECORDS", "No match found for name=%s, type=%s", nameNorm, rr.Type)
	return "", false
}

// writeLogMessageWithContext writes a formatted log entry to the
// provider's OperationLogger. When no logger is configured the call is
// a no-op.
func (p *Provider) writeLogMessageWithContext(logLevel, operationName, messageTemplate string, messageArguments ...interface{}) {
	if p.OperationLogger == nil {
		return
	}

	formattedMessage := fmt.Sprintf(messageTemplate, messageArguments...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	p.OperationLogger.Printf("[%s] [%s] [%s] %s", timestamp, logLevel, operationName, formattedMessage)
}

// writeDebugLogMessage emits a DEBUG-level log entry. Suppressed when
// EnableDebugLogging is false.
func (p *Provider) writeDebugLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	if !p.EnableDebugLogging {
		return
	}
	p.writeLogMessageWithContext("DEBUG", operationName, messageTemplate, messageArguments...)
}

// writeInfoLogMessage emits an INFO-level log entry.
func (p *Provider) writeInfoLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	p.writeLogMessageWithContext("INFO", operationName, messageTemplate, messageArguments...)
}

// writeErrorLogMessage emits an ERROR-level log entry.
func (p *Provider) writeErrorLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	p.writeLogMessageWithContext("ERROR", operationName, messageTemplate, messageArguments...)
}

// shouldRetryHTTPRequest reports whether a failed request should be
// retried based on the underlying error and HTTP status code.
func shouldRetryHTTPRequest(requestError error, httpStatusCode int) bool {
	switch httpStatusCode {
	case http.StatusConflict:
		return false
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}

	if requestError != nil {
		errMsg := requestError.Error()
		if strings.Contains(errMsg, "timeout") ||
			strings.Contains(errMsg, "connection refused") ||
			strings.Contains(errMsg, "no such host") ||
			strings.Contains(errMsg, "EOF") {
			return true
		}
	}

	return false
}

// effectiveRetryConfiguration returns the retry configuration to use
// for the next request. A zero-value HTTPRequestRetryConfiguration is
// treated as "use defaults"; any explicitly populated configuration is
// honoured as-is.
func (p *Provider) effectiveRetryConfiguration() HTTPRequestRetryConfiguration {
	if p.HTTPRequestRetryConfiguration == (HTTPRequestRetryConfiguration{}) {
		return CreateDefaultHTTPRequestRetryConfiguration()
	}
	return p.HTTPRequestRetryConfiguration
}

// calculateExponentialBackoffDelay computes the wait duration before
// the given retry attempt (0-indexed). The result is capped at
// MaximumRetryDelay.
func (p *Provider) calculateExponentialBackoffDelay(cfg HTTPRequestRetryConfiguration, retryAttemptNumber int) time.Duration {
	delay := time.Duration(float64(cfg.InitialRetryDelay) * math.Pow(cfg.ExponentialBackoffMultiplier, float64(retryAttemptNumber)))
	if delay > cfg.MaximumRetryDelay {
		delay = cfg.MaximumRetryDelay
	}
	return delay
}

// executeHTTPRequestWithRetryLogic runs an API request with retries
// based on the provider's HTTPRequestRetryConfiguration. The request
// body, if any, is buffered once so it can be replayed on each retry.
func (p *Provider) executeHTTPRequestWithRetryLogic(ctx context.Context, httpMethod, requestURL string, requestBody io.Reader, pathArguments ...interface{}) ([]byte, error) {
	requestURL = urlGenerator(requestURL, pathArguments...)
	p.writeDebugLogMessage("HTTP_REQUEST", "Starting %s request to %s", httpMethod, requestURL)

	var bodyBytes []byte
	if requestBody != nil {
		var err error
		bodyBytes, err = io.ReadAll(requestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	cfg := p.effectiveRetryConfiguration()
	var lastRequestError error

	for retryAttempt := 0; retryAttempt <= cfg.MaximumRetryAttempts; retryAttempt++ {
		if retryAttempt > 0 {
			backoffDelay := p.calculateExponentialBackoffDelay(cfg, retryAttempt-1)
			p.writeDebugLogMessage("HTTP_REQUEST", "Retry attempt %d/%d after %v delay", retryAttempt, cfg.MaximumRetryAttempts, backoffDelay)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDelay):
			}
		}

		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		responseData, requestError := p.executeSingleHTTPRequest(ctx, httpMethod, requestURL, bodyReader)
		if requestError == nil {
			if retryAttempt > 0 {
				p.writeInfoLogMessage("HTTP_REQUEST", "Request succeeded on attempt %d", retryAttempt+1)
			}
			return responseData, nil
		}

		lastRequestError = requestError

		var statusCode int
		var httpErr *httpError
		if errors.As(requestError, &httpErr) {
			statusCode = httpErr.StatusCode
		}

		p.writeErrorLogMessage("HTTP_REQUEST", "Request failed on attempt %d: %v", retryAttempt+1, requestError)

		if !shouldRetryHTTPRequest(requestError, statusCode) {
			p.writeDebugLogMessage("HTTP_REQUEST", "Error is not retryable, stopping retries")
			break
		}
	}

	p.writeErrorLogMessage("HTTP_REQUEST", "All retry attempts exhausted for %s %s", httpMethod, requestURL)
	return nil, fmt.Errorf("request failed after %d attempts: %w", cfg.MaximumRetryAttempts+1, lastRequestError)
}

// executeSingleHTTPRequest performs a single HTTP round-trip and
// returns either the response body or an error. Non-2xx responses are
// returned as *httpError so callers can react to specific status codes.
func (p *Provider) executeSingleHTTPRequest(ctx context.Context, httpMethod, requestURL string, requestBody io.Reader) ([]byte, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, httpMethod, requestURL, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpRequest.Header.Add("X-Auth-Token", p.KeystoneToken)
	httpRequest.Header.Add("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: cHTTPClientTimeout}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("request execution failed: %w", err)
	}
	defer httpResponse.Body.Close()

	responseBodyData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return nil, &httpError{
			StatusCode: httpResponse.StatusCode,
			Status:     http.StatusText(httpResponse.StatusCode),
			Body:       string(responseBodyData),
		}
	}

	return responseBodyData, nil
}
