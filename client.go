package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/libdns/libdns"
)

// init once. Get KeystoneToken
func (p *Provider) init(ctx context.Context) error {
	if p.OperationLogger == nil && p.EnableDebugLogging {
		p.OperationLogger = log.New(os.Stderr, "[selectel-libdns] ", log.LstdFlags)
	}
	
	p.writeInfoLogMessage("INIT", "Initializing provider with user: %s, account: %s, project: %s", p.User, p.AccountId, p.ProjectName)
	
	// Initialize default retry config if not set
	if p.HTTPRequestRetryConfiguration.MaximumRetryAttempts == 0 {
		p.HTTPRequestRetryConfiguration = CreateDefaultHTTPRequestRetryConfiguration()
		p.writeDebugLogMessage("INIT", "Using default retry config: %+v", p.HTTPRequestRetryConfiguration)
	}
	
	// create ZonesCache
	p.ZonesCache = make(map[string]string)
	p.writeDebugLogMessage("INIT", "Initialized zones cache")

	// Compile the template
	tmpl, err := template.New("getKeystoneToken").Parse(cGetKeystoneTokenTemplate)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to parse Keystone token template: %v", err)
		return fmt.Errorf("GetKeystoneTokenTemplate error: %w", err)
	}
	
	var tokensBody bytes.Buffer
	err = tmpl.Execute(&tokensBody, p)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to execute Keystone token template: %v", err)
		return fmt.Errorf("GetKeystoneTokenTemplate execute error: %w", err)
	}

	p.writeDebugLogMessage("INIT", "Requesting Keystone token from: %s", cTokensUrl)
	
	// Request a KeystoneToken
	request, err := http.NewRequestWithContext(ctx, httpMethods.post, cTokensUrl, &tokensBody)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to create Keystone token request: %v", err)
		return fmt.Errorf("getKeystoneToken NewRequestWithContext error: %w", err)
	}
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	response, err := client.Do(request)
	if err != nil {
		p.writeErrorLogMessage("INIT", "Failed to execute Keystone token request: %v", err)
		return fmt.Errorf("getKeystoneToken client.Do error: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		p.writeErrorLogMessage("INIT", "Keystone token request failed with status: %d %s", response.StatusCode, http.StatusText(response.StatusCode))
		err = fmt.Errorf("%s (%d)", http.StatusText(response.StatusCode), response.StatusCode)
		return fmt.Errorf("getKeystoneToken response.StatusCode error: %w", err)
	}

	// Getting header $KeystoneTokenHeader
	p.KeystoneToken = response.Header.Get(cKeystoneTokenHeader)
	if p.KeystoneToken == "" {
		p.writeErrorLogMessage("INIT", "Keystone token header '%s' is missing in response", cKeystoneTokenHeader)
		return fmt.Errorf("$KeystoneTokenHeader is missing")
	}

	p.writeInfoLogMessage("INIT", "Successfully obtained Keystone token")
	return nil
}

// Functional part of procedure GetRecords -> uniRecords
func (p *Provider) getRecords(ctx context.Context, zoneId string, zone string) ([]libdns.Record, error) {
	records, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}
	return mapRecordsToLibds(zone, records), nil
}

// Functional part of procedure AppendRecords -> uniRecords
func (p *Provider) appendRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	p.writeInfoLogMessage("APPEND_RECORDS", "Appending %d records to zone: %s (ID: %s)", len(records), zone, zoneId)
	
	var resultRecords []libdns.Record
	var resultErr error
	
	for i, libRecord := range records {
		rr := libRecord.RR()
		p.writeDebugLogMessage("APPEND_RECORDS", "Processing record %d/%d: %s %s", i+1, len(records), rr.Type, rr.Name)
		
		record := libdnsToRecord(zone, libRecord)
		// name normalizing
		body, err := json.Marshal(record)
		if err != nil {
			p.writeErrorLogMessage("APPEND_RECORDS", "Failed to marshal record %d: %v", i+1, err)
			resultErr = err
			continue
		}
		
		p.writeDebugLogMessage("APPEND_RECORDS", "Sending JSON to API: %s", string(body))
		
		// add recordset record request to api
		recordB, err := p.makeApiRequest(ctx, httpMethods.post, "/zones/%s/rrset", bytes.NewReader(body), zoneId)
		if err != nil {
			if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "already_exists") {
				p.writeInfoLogMessage("APPEND_RECORDS", "Record %d already exists, updating instead", i+1)
				zoneRecords, fetchErr := p.getSelectelRecords(ctx, zoneId)
				if fetchErr != nil {
					p.writeErrorLogMessage("APPEND_RECORDS", "Failed to fetch existing records: %v", fetchErr)
					resultErr = fetchErr
					continue
				}
				
			p.writeDebugLogMessage("APPEND_RECORDS", "Searching for record: type=%s, name=%s (libdns)", rr.Type, rr.Name)
			p.writeDebugLogMessage("APPEND_RECORDS", "Searching for record: type=%s, name=%s (API format)", record.Type, record.Name)
			p.writeDebugLogMessage("APPEND_RECORDS", "Zone name for comparison: %s", zone)
			for idx, zr := range zoneRecords {
				p.writeDebugLogMessage("APPEND_RECORDS", "Zone record %d: ID=%s, type=%s, name=%s", idx+1, zr.ID, zr.Type, zr.Name)
			}
			
				id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
				if exists {
					record.ID = id
					updatedRecord, updateErr := p.updateSelectelRecord(ctx, zone, zoneId, record)
					if updateErr != nil {
						p.writeErrorLogMessage("APPEND_RECORDS", "Failed to update existing record %d: %v", i+1, updateErr)
						resultErr = updateErr
						continue
					}
					libdnsRecord := recordToLibdns(zone, updatedRecord)
					resultRecords = append(resultRecords, libdnsRecord)
					p.writeDebugLogMessage("APPEND_RECORDS", "Successfully updated existing record %d: %s %s", i+1, rr.Type, rr.Name)
				} else {
					p.writeErrorLogMessage("APPEND_RECORDS", "Record exists but not found in zone records")
					resultErr = err
					continue
				}
			} else {
				p.writeErrorLogMessage("APPEND_RECORDS", "Failed to create record %d via API: %v", i+1, err)
				resultErr = err
				continue
			}
			continue
		}
		
		selRecord, err := deserialization[Record](recordB)
		if err != nil {
			p.writeErrorLogMessage("APPEND_RECORDS", "Failed to deserialize response for record %d: %v", i+1, err)
			resultErr = err
			continue
		}
		
		libdnsRecord := recordToLibdns(zone, selRecord)
		resultRecords = append(resultRecords, libdnsRecord)
		p.writeDebugLogMessage("APPEND_RECORDS", "Successfully created record %d: %s %s", i+1, rr.Type, rr.Name)
	}
	
	if resultErr != nil {
		p.writeErrorLogMessage("APPEND_RECORDS", "Some records failed to append: %v", resultErr)
	} else {
		p.writeInfoLogMessage("APPEND_RECORDS", "Successfully appended %d records to zone: %s", len(resultRecords), zone)
	}
	
	return resultRecords, resultErr
}

// Functional part of procedure SetRecords -> uniRecords
func (p *Provider) setRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	zoneRecords, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}

	var resultRecords []libdns.Record
	var resultErr error
	for _, libRecord := range records {
		// check for already exists
				id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
		if exists {
			// if zone recordset contain record
			upd := libdnsToRecord(zone, libRecord)
			upd.ID = id
			record, err := p.updateSelectelRecord(ctx, zone, zoneId, upd)
			if err != nil {
				resultErr = err
			} else {
				resultRecords = append(resultRecords, recordToLibdns(zone, record))				
			}
		} else {
			// if not contain
			libRecords_, err := p.appendRecords(ctx, zone, zoneId, []libdns.Record{libRecord})
			if err != nil {
				resultErr = err
			} else {
				resultRecords = append(resultRecords, libRecords_...)
			}
		}

	}
	return resultRecords, resultErr
}

// Functional part of procedure DeleteRecords -> uniRecords
func (p *Provider) deleteRecords(ctx context.Context, zone string, zoneId string, records []libdns.Record) ([]libdns.Record, error) {
	zoneRecords, err := p.getSelectelRecords(ctx, zoneId)
	if err != nil {
		return nil, err
	}

	var resultRecords []libdns.Record
	var resultErr error
	for _, libRecord := range records {
		// check for already exists
				id, exists := p.idFromRecordsByLibRecord(zoneRecords, libRecord, zone)
		if exists {
			// delete recordset record request to api
			_, err := p.makeApiRequest(ctx, httpMethods.delete, "/zones/%s/rrset/%s", nil, zoneId, id)
			if err != nil {
				resultErr = err
			} else {
				resultRecords = append(resultRecords, libRecord)
			}
		} else {
			rr := libRecord.RR()
			resultErr = fmt.Errorf("no %s record %s for delete", rr.Type, rr.Name)
		}
	}
	return resultRecords, resultErr
}


func (p *Provider) uniRecords(method string,ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// init
	var err error
	p.once.Do(func() {
		err = p.init(ctx)
	})
	
	if err != nil {
		p.once = sync.Once{} // reset p.once for next init
		return nil, err
	}
	
	// get zoneId
	zoneId, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	// calling the appropriate method
	var libRecords []libdns.Record
	switch method {
	case recordMethods.get:
		libRecords, err = p.getRecords(ctx, zoneId, zone)
	case recordMethods.append:
		libRecords, err = p.appendRecords(ctx, zone, zoneId, records)
	case recordMethods.set:
		libRecords, err = p.setRecords(ctx, zone, zoneId, records)
	case recordMethods.delete:
		libRecords, err = p.deleteRecords(ctx, zone, zoneId, records)
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	return libRecords, err
}

