package selectel

import (
	"bytes"
	"context"
	"encoding/json"
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

// Generic function to deserialize a JSON string into a variable of type T
func deserialization[T any](data []byte) (T, error) {
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	return result, nil
}


// Generate url from path
func urlGenerator(path string, args ...interface{}) string {
	return fmt.Sprintf(cApiBaseUrl+path, args...)
}

// API request function
// ctx - context
// method - http method (GET, POST, DELETE, PATCH, PUT)
// path - path to connect to apiBaseUrl
// body - data transferred in the body
// hideToken - flag for hiding the token in the header
// args - substitution arguments in path
func (p *Provider) makeApiRequest(ctx context.Context, method string, path string , body io.Reader, args ...interface{}) ([]byte, error) {	
	return p.executeHTTPRequestWithRetryLogic(ctx, method, path, body, args...)
}

// Get zoneId by zone name
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	p.writeDebugLogMessage("GET_ZONE_ID", "Looking up zone ID for zone: %s", zone)
	
	// try get zoneId from cache
	zoneId := p.ZonesCache[zone]
	if zoneId != "" {
		p.writeDebugLogMessage("GET_ZONE_ID", "Found zone ID in cache: %s", zoneId)
		return zoneId, nil
	}
	
	p.writeDebugLogMessage("GET_ZONE_ID", "Zone ID not in cache, fetching from API")
	
	// if not in cache, get from api
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
	
		zoneId = zones.Zones[0].ID
	p.writeInfoLogMessage("GET_ZONE_ID", "Found zone ID: %s for zone: %s", zoneId, zone)
	
	// Cache the zone ID
	p.ZonesCache[zone] = zoneId
	
	return zoneId, nil
}

// Convert Record to libdns.Record
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

// map []Record to []libdns.Record
func mapRecordsToLibds(zone string, records []Record) []libdns.Record {
	libdnsRecords := make([]libdns.Record, len(records))
	for i, record := range records {
		libdnsRecords[i] = recordToLibdns(zone, record)
	}
	return libdnsRecords
}

// Convert Record to libdns.Record
func libdnsToRecord(zone string, libdnsRecord libdns.Record) Record {
    rr := libdnsRecord.RR()

    ttl := rr.TTL.Seconds()
    if ttl == 0 {
        ttl = 60
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


// Get Selectel records
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

// Update Selectel record
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

// Normalize name in zone namespace
//
// test => test.zone.
// test.zone => test.zone.
// test.zone. => test.zone.
// test.subzone => test.subzone.zone.
// ...
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


// Check if an element with Id == id || (Name == name  && Type == type) exists 
func (p *Provider) idFromRecordsByLibRecord(records []Record, libRecord libdns.Record, zone string) (string, bool) {
	rr := libRecord.RR()
	
	// Convert zone to ASCII for proper comparison with IDN domains
	zoneASCII, err := idna.ToASCII(zone)
	if err != nil {
		zoneASCII = zone
	}
	
	nameNorm := strings.ToLower(strings.TrimSuffix(nameNormalizer(rr.Name, zoneASCII), "."))
	
	p.writeDebugLogMessage("ID_FROM_RECORDS", "Looking for record: nameNorm=%s, type=%s, zone=%s, zoneASCII=%s", nameNorm, rr.Type, zone, zoneASCII)
	
	for _, record := range records {
		// Convert record name to ASCII first, then normalize
		recordNameASCII, err := idna.ToASCII(strings.TrimSuffix(record.Name, "."))
		if err != nil {
			recordNameASCII = strings.TrimSuffix(record.Name, ".")
		}
		
		recordNameNorm := strings.ToLower(strings.TrimSuffix(nameNormalizer(recordNameASCII, zoneASCII), "."))
		
		p.writeDebugLogMessage("ID_FROM_RECORDS", "Checking record: original=%s, ASCII=%s, normalized=%s, type=%s", record.Name, recordNameASCII, recordNameNorm, record.Type)
		
		p.writeDebugLogMessage("ID_FROM_RECORDS", "Comparing: '%s' == '%s' && '%s' == '%s'", recordNameNorm, nameNorm, rr.Type, record.Type)
		
        if recordNameNorm == nameNorm && rr.Type == record.Type {
			p.writeDebugLogMessage("ID_FROM_RECORDS", "Match found! Returning ID: %s", record.ID)
			return record.ID ,true // Element found
		}
	}
	p.writeDebugLogMessage("ID_FROM_RECORDS", "No match found")
	return "", false // Element not found
}
// // map []Record to []libdns.Record
// func maplibdnsToRecord(libdnsRecords []libdns.Record) []Record {
// 	records := make([]Record, len(libdnsRecords))
// 	for i, record := range libdnsRecords {
// 		records[i] = libdnsToRecord(record)
// 	}
// 	return records
// }

func (p *Provider) writeLogMessageWithContext(logLevel, operationName, messageTemplate string, messageArguments ...interface{}) {
	if p.OperationLogger == nil {
		return
	}
	
	formattedMessage := fmt.Sprintf(messageTemplate, messageArguments...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	p.OperationLogger.Printf("[%s] [%s] [%s] %s", timestamp, logLevel, operationName, formattedMessage)
}

func (p *Provider) writeDebugLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	p.writeLogMessageWithContext("DEBUG", operationName, messageTemplate, messageArguments...)
}

func (p *Provider) writeInfoLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	p.writeLogMessageWithContext("INFO", operationName, messageTemplate, messageArguments...)
}

func (p *Provider) writeErrorLogMessage(operationName, messageTemplate string, messageArguments ...interface{}) {
	p.writeLogMessageWithContext("ERROR", operationName, messageTemplate, messageArguments...)
}

func shouldRetryHTTPRequestBasedOnErrorAndStatusCode(requestError error, httpStatusCode int) bool {
	if requestError != nil {
		if strings.Contains(requestError.Error(), "timeout") ||
		   strings.Contains(requestError.Error(), "connection refused") ||
		   strings.Contains(requestError.Error(), "no such host") {
			return true
		}
	}
	
	switch httpStatusCode {
	case 409:
		return false
	case 429, 500, 502, 503, 504:
		return true
	case 0:
		return requestError != nil
	}
	
	return false
}

func (p *Provider) calculateExponentialBackoffDelayForRetryAttempt(retryAttemptNumber int) time.Duration {
	retryConfiguration := p.HTTPRequestRetryConfiguration
	if retryConfiguration.MaximumRetryAttempts == 0 {
		retryConfiguration = CreateDefaultHTTPRequestRetryConfiguration()
	}
	
	delay := time.Duration(float64(retryConfiguration.InitialRetryDelay) * math.Pow(retryConfiguration.ExponentialBackoffMultiplier, float64(retryAttemptNumber)))
	if delay > retryConfiguration.MaximumRetryDelay {
		delay = retryConfiguration.MaximumRetryDelay
	}
	
	return delay
}

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
	
	retryConfiguration := p.HTTPRequestRetryConfiguration
	if retryConfiguration.MaximumRetryAttempts == 0 {
		retryConfiguration = CreateDefaultHTTPRequestRetryConfiguration()
	}
	
	var lastRequestError error
	var lastHTTPStatusCode int
	
	for retryAttempt := 0; retryAttempt <= retryConfiguration.MaximumRetryAttempts; retryAttempt++ {
		if retryAttempt > 0 {
			backoffDelay := p.calculateExponentialBackoffDelayForRetryAttempt(retryAttempt - 1)
			p.writeDebugLogMessage("HTTP_REQUEST", "Retry attempt %d/%d after %v delay", retryAttempt, retryConfiguration.MaximumRetryAttempts, backoffDelay)
			
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
		
		if strings.Contains(requestError.Error(), "(") {
			fmt.Sscanf(requestError.Error(), "%*s (%d)", &lastHTTPStatusCode)
		}
		
		p.writeErrorLogMessage("HTTP_REQUEST", "Request failed on attempt %d: %v", retryAttempt+1, requestError)
		
		if !shouldRetryHTTPRequestBasedOnErrorAndStatusCode(requestError, lastHTTPStatusCode) {
			p.writeDebugLogMessage("HTTP_REQUEST", "Error is not retryable, stopping retries")
			break
		}
		
		if retryAttempt < retryConfiguration.MaximumRetryAttempts {
			p.writeDebugLogMessage("HTTP_REQUEST", "Retrying request due to retryable error")
		}
	}
	
	p.writeErrorLogMessage("HTTP_REQUEST", "All retry attempts exhausted for %s %s", httpMethod, requestURL)
	return nil, fmt.Errorf("request failed after %d attempts: %w", retryConfiguration.MaximumRetryAttempts+1, lastRequestError)
}

func (p *Provider) executeSingleHTTPRequest(ctx context.Context, httpMethod, requestURL string, requestBody io.Reader) ([]byte, error) {
	httpRequest, requestCreationError := http.NewRequestWithContext(ctx, httpMethod, requestURL, requestBody)
	if requestCreationError != nil {
		return nil, fmt.Errorf("failed to create request: %w", requestCreationError)
	}

	httpRequest.Header.Add("X-Auth-Token", p.KeystoneToken)
	httpRequest.Header.Add("Content-Type", "application/json")

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	httpResponse, requestExecutionError := httpClient.Do(httpRequest)
	if requestExecutionError != nil {
		return nil, fmt.Errorf("request execution failed: %w", requestExecutionError)
	}

	defer httpResponse.Body.Close()

	responseBodyData, responseBodyReadError := io.ReadAll(httpResponse.Body)
	if responseBodyReadError != nil {
		return nil, fmt.Errorf("failed to read response body: %w", responseBodyReadError)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return nil, fmt.Errorf("%s (%d): %s", http.StatusText(httpResponse.StatusCode), httpResponse.StatusCode, string(responseBodyData))
	}

	return responseBodyData, nil
}