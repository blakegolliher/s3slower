// Package terminal provides terminal output tests.
package terminal

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/http"
)

// TestNewWriter tests the NewWriter function.
func TestNewWriter(t *testing.T) {
	t.Run("creates_with_defaults", func(t *testing.T) {
		w := NewWriter(nil, OutputModeTable, 0)

		assert.NotNil(t, w)
		assert.Equal(t, 50, w.maxURLLen)
	})

	t.Run("respects_custom_max_url_len", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 100)

		assert.Equal(t, 100, w.maxURLLen)
	})
}

// TestWriteHeader tests the WriteHeader method.
func TestWriteHeader(t *testing.T) {
	t.Run("table_mode_writes_header", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		w.WriteHeader()

		output := buf.String()
		assert.Contains(t, output, "TIME")
		assert.Contains(t, output, "PROC")
		assert.Contains(t, output, "OP")
		assert.Contains(t, output, "STAT")
		assert.Contains(t, output, "BUCKET")
		assert.Contains(t, output, "ENDPOINT")
		assert.Contains(t, output, "BYTES")
		assert.Contains(t, output, "LAT(ms)")
		assert.Contains(t, output, "KEY")
	})

	t.Run("header_only_written_once", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		w.WriteHeader()
		firstLen := buf.Len()

		w.WriteHeader()
		secondLen := buf.Len()

		assert.Equal(t, firstLen, secondLen)
	})

	t.Run("simple_mode_no_header", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeSimple, 50)

		w.WriteHeader()

		assert.Empty(t, buf.String())
	})
}

// TestWriteEvent tests the WriteEvent method.
func TestWriteEvent(t *testing.T) {
	makeTestEvent := func() *event.S3Event {
		return &event.S3Event{
			Timestamp:    time.Date(2024, 1, 15, 10, 30, 45, 123000000, time.UTC),
			PID:          12345,
			Comm:         "aws",
			ClientType:   "aws-cli",
			Method:       "GET",
			Operation:    http.OpGetObject,
			Bucket:       "mybucket",
			LatencyMs:    123.45,
			StatusCode:   200,
			ResponseSize: 1024,
		}
	}

	t.Run("table_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		e := makeTestEvent()
		e.Path = "/mybucket/data/mykey.json"
		e.Endpoint = "s3.us-east-1"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "10:30:45")
		assert.Contains(t, output, "GET")
		assert.Contains(t, output, "mybucket")
		assert.Contains(t, output, "s3.us-east-1")
		assert.Contains(t, output, "1024")
		assert.Contains(t, output, "123.45")
		assert.Contains(t, output, " 200 ")
		assert.Contains(t, output, "aws-cli")
		assert.Contains(t, output, "data/mykey.json")
	})

	t.Run("table_mode_ranged_get", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		e := makeTestEvent()
		e.Operation = http.OpGetObjectRange
		e.Path = "/mybucket/shard-0001.tar"
		e.Range = "bytes=0-65535"
		e.StatusCode = 206
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "GET_RNG")
		assert.Contains(t, output, " 206 ")
		assert.Contains(t, output, "shard-0001.tar [bytes=0-65535]")
	})

	t.Run("table_mode_truncates_long_keys_from_left", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 20)

		e := makeTestEvent()
		e.Path = "/mybucket/very/deep/prefix/for/training/shard-0001.tar"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "...ng/shard-0001.tar")
		assert.NotContains(t, output, "very/deep")
	})

	t.Run("table_mode_bucket_query_key", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		e := makeTestEvent()
		e.Method = "POST"
		e.Operation = http.OpDeleteObjects
		e.Path = "/mybucket?delete"
		e.RequestSize = 4096
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "DEL_BULK")
		assert.NotContains(t, output, "delete")
		assert.Contains(t, output, "4096")
	})

	t.Run("table_mode_key_column", func(t *testing.T) {
		cases := []struct {
			op   http.S3Operation
			path string
			want string
		}{
			{http.OpMPUPart, "/mybucket/ckpt/step-1.pt?uploadId=123&partNumber=4", "ckpt/step-1.pt"},
			{http.OpListPrefix, "/mybucket?list-type=2&prefix=train%2Fshards%2F&delimiter=%2F", "train/shards/*"},
			{http.OpListObjects, "/mybucket/", "*"},
			{http.OpGetObject, "/mybucket/a/b.tar", "a/b.tar"},
		}
		for _, c := range cases {
			e := makeTestEvent()
			e.Operation, e.Path = c.op, c.path
			assert.Equal(t, c.want, displayKey(e), c.path)
		}
	})

	t.Run("simple_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeSimple, 50)

		e := makeTestEvent()
		e.Path = "/mybucket/mykey"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "12345")
		assert.Contains(t, output, "aws")
		assert.Contains(t, output, "GET")
		assert.Contains(t, output, "123.45ms")
	})

	t.Run("json_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeJSON, 50)

		e := makeTestEvent()
		e.Path = "/mybucket/mykey"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, `"pid":12345`)
		assert.Contains(t, output, `"comm":"aws"`)
		assert.Contains(t, output, `"method":"GET"`)
		assert.Contains(t, output, `"latency_ms":123.45`)
		assert.Contains(t, output, `"status_code":200`)
		assert.NotContains(t, output, `"range"`)

		buf.Reset()
		e.Range = "bytes=-8192"
		w.WriteEvent(e)
		assert.Contains(t, buf.String(), `"range":"bytes=-8192"`)
	})
}

// TestAbbreviateOp checks every operation fits the 8-character OP column.
func TestAbbreviateOp(t *testing.T) {
	ops := []http.S3Operation{
		http.OpGetObject, http.OpGetObjectRange, http.OpPutObject, http.OpCopyObject,
		http.OpDeleteObject, http.OpDeleteObjects, http.OpHeadObject, http.OpListObjects,
		http.OpListPrefix, http.OpListBuckets, http.OpMPUCreate, http.OpMPUPart,
		http.OpMPUComplete, http.OpMPUAbort, http.OpMPUList, http.OpMPUListParts,
		http.OpCreateBucket, http.OpDeleteBucket, http.OpHeadBucket, http.OpBucketConfig,
		http.OpUnknown,
	}
	seen := map[string]http.S3Operation{}
	for _, op := range ops {
		abbr := abbreviateOp(string(op))
		assert.LessOrEqual(t, len(abbr), 8, "%s -> %s", op, abbr)
		if prev, dup := seen[abbr]; dup {
			t.Errorf("%s and %s both abbreviate to %s", prev, op, abbr)
		}
		seen[abbr] = op
	}
}

// TestOutputModes tests the output mode constants.
func TestOutputModes(t *testing.T) {
	assert.Equal(t, OutputMode(0), OutputModeTable)
	assert.Equal(t, OutputMode(1), OutputModeSimple)
	assert.Equal(t, OutputMode(2), OutputModeJSON)
}
