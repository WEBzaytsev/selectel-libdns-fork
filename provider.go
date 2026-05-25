// Package selectel implements a DNS record management client compatible
// with the libdns interfaces for selectel v2.
package selectel

import (
	"context"
	"log"
	"sync"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Selectel DNS v2 API.
type Provider struct {
	// User is the Selectel service user login (required).
	User string `json:"user,omitempty"`
	// Password is the Selectel service user password (required).
	Password string `json:"password,omitempty"`
	// AccountId is the Selectel account ID (required).
	AccountId string `json:"account_id,omitempty"`
	// ProjectName is the Selectel project name (required).
	ProjectName string `json:"project_name,omitempty"`

	// EnableDebugLogging enables verbose DEBUG-level messages on the
	// OperationLogger. INFO and ERROR messages are emitted regardless
	// of this flag as long as OperationLogger is set.
	EnableDebugLogging bool `json:"enable_debug_logging,omitempty"`

	// HTTPRequestRetryConfiguration controls the retry behaviour for
	// transient HTTP failures. A zero value enables sensible defaults
	// (see CreateDefaultHTTPRequestRetryConfiguration).
	HTTPRequestRetryConfiguration HTTPRequestRetryConfiguration

	// OperationLogger receives diagnostic messages. When nil and
	// EnableDebugLogging is true, a logger writing to os.Stderr is
	// created automatically. When nil and EnableDebugLogging is false,
	// the provider is completely silent.
	OperationLogger *log.Logger

	// KeystoneToken holds the active Selectel Keystone token. It is
	// populated lazily on the first API call.
	KeystoneToken string
	// ZonesCache caches resolved zone IDs by zone name.
	ZonesCache map[string]string

	once  sync.Once
	mutex sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.uniRecords(recordMethods.get, ctx, zone, nil)
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.uniRecords(recordMethods.append, ctx, zone, records)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.uniRecords(recordMethods.set, ctx, zone, records)
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.uniRecords(recordMethods.delete, ctx, zone, records)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
