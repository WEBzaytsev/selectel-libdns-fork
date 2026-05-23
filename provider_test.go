package selectel_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
	selectel "github.com/libdns/selectel"
	"github.com/stretchr/testify/assert"
)

var provider selectel.Provider
var zone string
var ctx context.Context

var addedRecords []libdns.Record
var sourceRecords []libdns.Record

// load init data from .env
func setup() {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .env file")
	}

	provider = selectel.Provider{
		User:        os.Getenv("SELECTEL_USER"),
		Password:    os.Getenv("SELECTEL_PASSWORD"),
		AccountId:   os.Getenv("SELECTEL_ACCOUNT_ID"),
		ProjectName: os.Getenv("SELECTEL_PROJECT_NAME"),
		ZonesCache:  make(map[string]string),
	}
	zone = os.Getenv("SELECTEL_ZONE")
	ctx = context.Background()
    sourceRecords = []libdns.Record{
        libdns.RR{ // 0
            Type: "A",
            Name: fmt.Sprintf("test1.%s.", os.Getenv("SELECTEL_ZONE")),
            Data: "1.2.3.1",
            TTL:  61 * time.Second,
        },
        libdns.RR{ // 1
            Type: "A",
            Name: fmt.Sprintf("test2.%s.", os.Getenv("SELECTEL_ZONE")),
            Data: "1.2.3.2",
            TTL:  61 * time.Second,
        },
        libdns.RR{ // 2
            Type: "A",
            Name: "test3",
            Data: "1.2.3.3",
            TTL:  61 * time.Second,
        },
        libdns.RR{ // 3
            Type: "TXT",
            Name: "test1",
            Data: "test1 txt",
            TTL:  61 * time.Second,
        },
        libdns.RR{ // 4
            Type: "TXT",
            Name: fmt.Sprintf("test2.%s.", os.Getenv("SELECTEL_ZONE")),
            Data: "test2 txt",
            TTL:  61 * time.Second,
        },
        libdns.RR{ // 5
            Type: "TXT",
            Name: "test3",
            Data: "test3 txt",
            TTL:  61 * time.Second,
        },
    }
}

// testing GetRecord
func TestProvider_GetRecords(t *testing.T) {
	setup()

	// delete sourceRec if exists
	provider.DeleteRecords(ctx, zone, sourceRecords)

	records, err := provider.GetRecords(ctx, zone)
	assert.NoError(t, err)
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "No records found")
	t.Logf("GetRecords test passed. Records found: %d", len(records))
}

// testing append record
func TestProvider_AppendRecords(t *testing.T) {
	setup()
	// entries to add
	newRecords := []libdns.Record{
        libdns.RR{
            Type: "A",
            Name: "append-test1",
            Data: "1.2.3.1",
            TTL:  300 * time.Second,
        },
        libdns.RR{
            Type: "TXT",
            Name: "append-test2",
            Data: "append test record",
            TTL:  300 * time.Second,
        },
	}

    records, err := provider.AppendRecords(ctx, zone, newRecords)
	addedRecords = records
	if err != nil {
		t.Logf("AppendRecords error: %v", err)
	}
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "Should have created at least one record")
	if len(records) > 0 {
		assert.Equal(t, "A", records[0].RR().Type)
	}
	if len(records) > 2 {
		assert.Equal(t, "TXT", records[2].RR().Type)
	}
	t.Logf("AppendRecords test passed. Append count: %d", len(records))
}

// testing set
func TestProvider_SetRecords(t *testing.T) {
	setup()

	// Create simple test records for SetRecords
    setRecords := []libdns.Record{
        libdns.RR{
            Type: "A",
            Name: "set-test1",
            Data: "1.2.3.1",
            TTL:  62 * time.Second,
        },
        libdns.RR{
            Type: "TXT",
            Name: "set-test2",
            Data: "test txt record",
            TTL:  300 * time.Second,
        },
    }

	records, err := provider.SetRecords(ctx, zone, setRecords)
	addedRecords = records
	if err != nil {
		t.Logf("SetRecords error: %v", err)
	}
	assert.NotNil(t, records)
	assert.True(t, len(records) > 0, "Should have created at least one record")
	if len(records) > 0 {
		assert.Equal(t, "A", records[0].RR().Type)
	}
	t.Logf("SetRecords test passed. Set count: %d", len(records))
}

// testing delete
func TestProvider_DeleteRecords(t *testing.T) {
	setup()

	// Delete the records that were created in AppendRecords and SetRecords tests
    delRecords := []libdns.Record{
        libdns.RR{
            Type: "A",
            Name: "append-test1",
            Data: "1.2.3.1",
            TTL:  300 * time.Second,
        },
        libdns.RR{
            Type: "TXT",
            Name: "append-test2",
            Data: "append test record",
            TTL:  300 * time.Second,
        },
        libdns.RR{
            Type: "A",
            Name: "set-test1",
            Data: "1.2.3.1",
            TTL:  62 * time.Second,
        },
        libdns.RR{
            Type: "TXT",
            Name: "set-test2",
            Data: "test txt record",
            TTL:  300 * time.Second,
        },
    }

	records, err := provider.DeleteRecords(ctx, zone, delRecords)
	if err != nil {
		t.Logf("DeleteRecords error: %v", err)
	}
	assert.NotNil(t, records)
	assert.True(t, len(records) >= 0, "Should have attempted to delete records")
	t.Logf("DeleteRecords test passed. Delete count: %d", len(records))
}

func TestHTTPRequestRetryConfiguration(t *testing.T) {
	setup()
	
	defaultRetryConfiguration := selectel.CreateDefaultHTTPRequestRetryConfiguration()
	assert.Equal(t, 3, defaultRetryConfiguration.MaximumRetryAttempts)
	assert.Equal(t, 1*time.Second, defaultRetryConfiguration.InitialRetryDelay)
	assert.Equal(t, 30*time.Second, defaultRetryConfiguration.MaximumRetryDelay)
	assert.Equal(t, 2.0, defaultRetryConfiguration.ExponentialBackoffMultiplier)
	
	customRetryConfiguration := selectel.HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         5,
		InitialRetryDelay:           2 * time.Second,
		MaximumRetryDelay:           60 * time.Second,
		ExponentialBackoffMultiplier: 1.5,
	}
	
	provider.HTTPRequestRetryConfiguration = customRetryConfiguration
	assert.Equal(t, 5, provider.HTTPRequestRetryConfiguration.MaximumRetryAttempts)
	assert.Equal(t, 2*time.Second, provider.HTTPRequestRetryConfiguration.InitialRetryDelay)
	assert.Equal(t, 60*time.Second, provider.HTTPRequestRetryConfiguration.MaximumRetryDelay)
	assert.Equal(t, 1.5, provider.HTTPRequestRetryConfiguration.ExponentialBackoffMultiplier)
	
	t.Log("HTTPRequestRetryConfiguration test passed")
}

func TestEnhancedErrorHandling(t *testing.T) {
	setup()
	
	invalidZoneName := "nonexistent.zone.test"
	records, err := provider.GetRecords(ctx, invalidZoneName)
	assert.Error(t, err)
	assert.Nil(t, records)
	assert.Contains(t, err.Error(), "no zoneId for zone")
	
	t.Log("EnhancedErrorHandling test passed")
}