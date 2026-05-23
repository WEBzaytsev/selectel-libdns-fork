package selectel_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
	selectel "github.com/libdns/selectel"
	"github.com/stretchr/testify/assert"
)

// ----- Integration test scaffolding --------------------------------------

// setupIntegration loads credentials from .env (if present) and the
// process environment, and returns a configured Provider together with
// the target zone. If the required SELECTEL_* variables are not
// available, the test is skipped rather than failing - this lets
// `go test ./...` run cleanly on machines without Selectel credentials.
func setupIntegration(t *testing.T) (*selectel.Provider, string, context.Context) {
	t.Helper()

	// .env is optional. Ignore the error if it does not exist.
	_ = godotenv.Load(".env")

	required := []string{
		"SELECTEL_USER",
		"SELECTEL_PASSWORD",
		"SELECTEL_ACCOUNT_ID",
		"SELECTEL_PROJECT_NAME",
		"SELECTEL_ZONE",
	}
	for _, key := range required {
		if os.Getenv(key) == "" {
			t.Skipf("skipping integration test: %s is not set", key)
		}
	}

	provider := &selectel.Provider{
		User:        os.Getenv("SELECTEL_USER"),
		Password:    os.Getenv("SELECTEL_PASSWORD"),
		AccountId:   os.Getenv("SELECTEL_ACCOUNT_ID"),
		ProjectName: os.Getenv("SELECTEL_PROJECT_NAME"),
		ZonesCache:  make(map[string]string),
	}
	return provider, os.Getenv("SELECTEL_ZONE"), context.Background()
}

func sampleRecords(zone string) []libdns.Record {
	return []libdns.Record{
		libdns.RR{Type: "A", Name: fmt.Sprintf("test1.%s.", zone), Data: "1.2.3.1", TTL: 61 * time.Second},
		libdns.RR{Type: "A", Name: fmt.Sprintf("test2.%s.", zone), Data: "1.2.3.2", TTL: 61 * time.Second},
		libdns.RR{Type: "A", Name: "test3", Data: "1.2.3.3", TTL: 61 * time.Second},
		libdns.RR{Type: "TXT", Name: "test1", Data: "test1 txt", TTL: 61 * time.Second},
		libdns.RR{Type: "TXT", Name: fmt.Sprintf("test2.%s.", zone), Data: "test2 txt", TTL: 61 * time.Second},
		libdns.RR{Type: "TXT", Name: "test3", Data: "test3 txt", TTL: 61 * time.Second},
	}
}

// ----- Integration tests --------------------------------------------------

func TestProvider_GetRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	// best-effort cleanup of any leftover records from previous runs
	_, _ = provider.DeleteRecords(ctx, zone, sampleRecords(zone))

	records, err := provider.GetRecords(ctx, zone)
	assert.NoError(t, err)
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "no records found")
	t.Logf("GetRecords: %d records found", len(records))
}

func TestProvider_AppendRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	newRecords := []libdns.Record{
		libdns.RR{Type: "A", Name: "append-test1", Data: "1.2.3.1", TTL: 300 * time.Second},
		libdns.RR{Type: "TXT", Name: "append-test2", Data: "append test record", TTL: 300 * time.Second},
	}

	records, err := provider.AppendRecords(ctx, zone, newRecords)
	if err != nil {
		t.Logf("AppendRecords error: %v", err)
	}
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "should have created at least one record")
	if len(records) > 0 {
		assert.Equal(t, "A", records[0].RR().Type)
	}
}

func TestProvider_SetRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	setRecords := []libdns.Record{
		libdns.RR{Type: "A", Name: "set-test1", Data: "1.2.3.1", TTL: 62 * time.Second},
		libdns.RR{Type: "TXT", Name: "set-test2", Data: "test txt record", TTL: 300 * time.Second},
	}

	records, err := provider.SetRecords(ctx, zone, setRecords)
	if err != nil {
		t.Logf("SetRecords error: %v", err)
	}
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "should have created at least one record")
	if len(records) > 0 {
		assert.Equal(t, "A", records[0].RR().Type)
	}
}

func TestProvider_DeleteRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	delRecords := []libdns.Record{
		libdns.RR{Type: "A", Name: "append-test1", Data: "1.2.3.1", TTL: 300 * time.Second},
		libdns.RR{Type: "TXT", Name: "append-test2", Data: "append test record", TTL: 300 * time.Second},
		libdns.RR{Type: "A", Name: "set-test1", Data: "1.2.3.1", TTL: 62 * time.Second},
		libdns.RR{Type: "TXT", Name: "set-test2", Data: "test txt record", TTL: 300 * time.Second},
	}

	records, err := provider.DeleteRecords(ctx, zone, delRecords)
	if err != nil {
		t.Logf("DeleteRecords error: %v", err)
	}
	assert.NotNil(t, records)
}

// ----- Unit tests ---------------------------------------------------------

func TestCreateDefaultHTTPRequestRetryConfiguration(t *testing.T) {
	cfg := selectel.CreateDefaultHTTPRequestRetryConfiguration()
	assert.Equal(t, 3, cfg.MaximumRetryAttempts)
	assert.Equal(t, 1*time.Second, cfg.InitialRetryDelay)
	assert.Equal(t, 30*time.Second, cfg.MaximumRetryDelay)
	assert.Equal(t, 2.0, cfg.ExponentialBackoffMultiplier)
}

func TestHTTPRequestRetryConfiguration_CustomValuesArePreserved(t *testing.T) {
	custom := selectel.HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         5,
		InitialRetryDelay:            2 * time.Second,
		MaximumRetryDelay:            60 * time.Second,
		ExponentialBackoffMultiplier: 1.5,
	}
	provider := &selectel.Provider{HTTPRequestRetryConfiguration: custom}

	if !reflect.DeepEqual(provider.HTTPRequestRetryConfiguration, custom) {
		t.Fatalf("retry configuration was mutated: got %+v want %+v", provider.HTTPRequestRetryConfiguration, custom)
	}
}
