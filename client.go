package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"text/template"

	"github.com/libdns/libdns"
)

// init authenticates with the Selectel Keystone identity service and
// caches a session token on the provider. It is run exactly once per
// provider instance via sync.Once and re-armed on failure so the next
// API call can retry the handshake.
func (p *Provider) init(ctx context.Context) error {
	if p.OperationLogger == nil && p.EnableDebugLogging {
		p.OperationLogger = log.New(os.Stderr, "[selectel-libdns] ", log.LstdFlags)
	}

	p.writeInfoLogMessage("INIT", "Initializing provider with user: %s, account: %s, project: %s", p.User, p.AccountId, p.ProjectName)

	if p.ZonesCache == nil {
		p.ZonesCache = make(map[string]string)
		p.writeDebugLogMessage("INIT", "Initialized zones cache")
	}

	tmpl, err := template.New("getKeystoneToken").Parse(cGetKeystoneTokenTemplate)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to parse Keystone token template: %v", err)
		return fmt.Errorf("parse keystone token template: %w", err)
	}

	var tokensBody bytes.Buffer
	if err := tmpl.Execute(&tokensBody, p); err != nil {
		p.writeErrorLogMessage("INIT", "Failed to execute Keystone token template: %v", err)
		return fmt.Errorf("execute keystone token template: %w", err)
	}

	p.writeDebugLogMessage("INIT", "Requesting Keystone token from: %s", cTokensUrl)

	request, err := http.NewRequestWithContext(ctx, httpMethods.post, cTokensUrl, &tokensBody)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to create Keystone token request: %v", err)
		return fmt.Errorf("create keystone token request: %w", err)
	}
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: cHTTPClientTimeout}
	response, err := client.Do(request)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to execute Keystone token request: %v", err)
		return fmt.Errorf("execute keystone token request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		p.writeErrorLogMessage("INIT", "Keystone token request failed with status: %d %s", response.StatusCode, http.StatusText(response.StatusCode))
		return fmt.Errorf("keystone token request: %s (%d)", http.StatusText(response.StatusCode), response.StatusCode)
	}

	p.KeystoneToken = response.Header.Get(cKeystoneTokenHeader)
	if p.KeystoneToken == "" {
		p.writeErrorLogMessage("INIT", "Keystone token header '%s' is missing in response", cKeystoneTokenHeader)
		return fmt.Errorf("keystone token header %q is missing in response", cKeystoneTokenHeader)
	}

	p.writeInfoLogMessage("INIT", "Successfully obtained Keystone token")
	return nil
}

// getRecords powers the public GetRecords method.
func (p *Provider) getRecords(ctx context.Context, zoneId string, zone string) ([]libdns.Record, error) {
	records, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}
	return mapRecordsToLibds(zone, records), nil
}

// isConflictError reports whether err is an HTTP 409 Conflict response
// from the Selectel API.
func isConflictError(err error) bool {
	var httpErr *httpError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict
}

// appendRecords powers the public AppendRecords method. When the API
// returns 409 Conflict for a record it already knows about, the record
// is updated in place instead of failing.
func (p *Provider) appendRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	p.writeInfoLogMessage("APPEND_RECORDS", "Appending %d records to zone: %s (ID: %s)", len(records), zone, zoneId)

	var resultRecords []libdns.Record
	var resultErr error

	for i, libRecord := range records {
		rr := libRecord.RR()
		p.writeDebugLogMessage("APPEND_RECORDS", "Processing record %d/%d: %s %s", i+1, len(records), rr.Type, rr.Name)

		record := libdnsToRecord(zone, libRecord)
		body, err := json.Marshal(record)
		if err != nil {
			p.writeErrorLogMessage("APPEND_RECORDS", "Failed to marshal record %d: %v", i+1, err)
			resultErr = err
			continue
		}

		p.writeDebugLogMessage("APPEND_RECORDS", "Sending JSON to API: %s", string(body))

		recordB, err := p.makeApiRequest(ctx, httpMethods.post, "/zones/%s/rrset", bytes.NewReader(body), zoneId)
		if err != nil {
			if !isConflictError(err) {
				p.writeErrorLogMessage("APPEND_RECORDS", "Failed to create record %d via API: %v", i+1, err)
				resultErr = err
				continue
			}

			p.writeInfoLogMessage("APPEND_RECORDS", "Record %d already exists, updating instead", i+1)
			zoneRecords, fetchErr := p.getSelectelRecords(ctx, zoneId)
			if fetchErr != nil {
				p.writeErrorLogMessage("APPEND_RECORDS", "Failed to fetch existing records: %v", fetchErr)
				resultErr = fetchErr
				continue
			}

			id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
			if !exists {
				p.writeErrorLogMessage("APPEND_RECORDS", "Record %d reported as conflict but not found in zone records", i+1)
				resultErr = err
				continue
			}

			record.ID = id
			updatedRecord, updateErr := p.updateSelectelRecord(ctx, zone, zoneId, record)
			if updateErr != nil {
				p.writeErrorLogMessage("APPEND_RECORDS", "Failed to update existing record %d: %v", i+1, updateErr)
				resultErr = updateErr
				continue
			}

			resultRecords = append(resultRecords, recordToLibdns(zone, updatedRecord))
			p.writeDebugLogMessage("APPEND_RECORDS", "Successfully updated existing record %d: %s %s", i+1, rr.Type, rr.Name)
			continue
		}

		selRecord, err := deserialization[Record](recordB)
		if err != nil {
			p.writeErrorLogMessage("APPEND_RECORDS", "Failed to deserialize response for record %d: %v", i+1, err)
			resultErr = err
			continue
		}

		resultRecords = append(resultRecords, recordToLibdns(zone, selRecord))
		p.writeDebugLogMessage("APPEND_RECORDS", "Successfully created record %d: %s %s", i+1, rr.Type, rr.Name)
	}

	if resultErr != nil {
		p.writeErrorLogMessage("APPEND_RECORDS", "Some records failed to append: %v", resultErr)
	} else {
		p.writeInfoLogMessage("APPEND_RECORDS", "Successfully appended %d records to zone: %s", len(resultRecords), zone)
	}

	return resultRecords, resultErr
}

// setRecords powers the public SetRecords method.
func (p *Provider) setRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	zoneRecords, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}

	var resultRecords []libdns.Record
	var resultErr error
	for _, libRecord := range records {
		id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
		if exists {
			upd := libdnsToRecord(zone, libRecord)
			upd.ID = id
			record, err := p.updateSelectelRecord(ctx, zone, zoneId, upd)
			if err != nil {
				resultErr = err
				continue
			}
			resultRecords = append(resultRecords, recordToLibdns(zone, record))
			continue
		}

		appended, err := p.appendRecords(ctx, zone, zoneId, []libdns.Record{libRecord})
		if err != nil {
			resultErr = err
			continue
		}
		resultRecords = append(resultRecords, appended...)
	}
	return resultRecords, resultErr
}

// deleteRecords powers the public DeleteRecords method.
func (p *Provider) deleteRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	zoneRecords, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}

	var resultRecords []libdns.Record
	var resultErr error
	for _, libRecord := range records {
		id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
		if !exists {
			rr := libRecord.RR()
			resultErr = fmt.Errorf("no %s record %s for delete", rr.Type, rr.Name)
			continue
		}

		if _, err := p.makeApiRequest(ctx, httpMethods.delete, "/zones/%s/rrset/%s", nil, zoneId, id); err != nil {
			resultErr = err
			continue
		}
		resultRecords = append(resultRecords, libRecord)
	}
	return resultRecords, resultErr
}

// uniRecords is the shared dispatcher used by all four public CRUD
// methods. It performs lazy authentication, resolves the zone ID and
// routes the call to the appropriate handler.
func (p *Provider) uniRecords(method string, ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var err error
	p.once.Do(func() {
		err = p.init(ctx)
	})
	if err != nil {
		p.once = sync.Once{} // re-arm init for the next call
		return nil, err
	}

	zoneId, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	switch method {
	case recordMethods.get:
		return p.getRecords(ctx, zoneId, zone)
	case recordMethods.append:
		return p.appendRecords(ctx, zone, zoneId, records)
	case recordMethods.set:
		return p.setRecords(ctx, zone, zoneId, records)
	case recordMethods.delete:
		return p.deleteRecords(ctx, zone, zoneId, records)
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
}
