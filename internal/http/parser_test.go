// Package http provides HTTP request/response parsing tests.
package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseHTTPRequest tests the ParseHTTPRequest function.
func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name          string
		raw           []byte
		wantMethod    string
		wantHost      string
		wantPath      string
		wantContentLen int
	}{
		// Valid requests
		{
			name:          "valid_get_request",
			raw:           []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 0\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:          "valid_put_request_with_content_length",
			raw:           []byte("PUT /mybucket/mykey.txt HTTP/1.1\r\nHost: minio.local:9000\r\nContent-Length: 1048576\r\n\r\n"),
			wantMethod:    "PUT",
			wantHost:      "minio.local:9000",
			wantPath:      "/mybucket/mykey.txt",
			wantContentLen: 1048576,
		},
		{
			name:          "valid_post_request",
			raw:           []byte("POST /bucket/key?uploads HTTP/1.1\r\nHost: s3.us-west-2.amazonaws.com\r\n\r\n"),
			wantMethod:    "POST",
			wantHost:      "s3.us-west-2.amazonaws.com",
			wantPath:      "/bucket/key?uploads",
			wantContentLen: 0,
		},
		{
			name:          "valid_delete_request",
			raw:           []byte("DELETE /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "DELETE",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:          "valid_head_request",
			raw:           []byte("HEAD /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "HEAD",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 0,
		},

		// Missing headers
		{
			name:          "missing_host_header",
			raw:           []byte("GET /bucket/key HTTP/1.1\r\nContent-Length: 100\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "",
			wantPath:      "/bucket/key",
			wantContentLen: 100,
		},
		{
			name:          "missing_content_length",
			raw:           []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 0,
		},

		// Case insensitivity
		{
			name:          "case_insensitive_headers",
			raw:           []byte("GET /bucket/key HTTP/1.1\r\nhOsT: s3.amazonaws.com\r\ncontent-LENGTH: 512\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 512,
		},

		// Edge cases
		{
			name:          "empty_input",
			raw:           []byte(""),
			wantMethod:    "",
			wantHost:      "",
			wantPath:      "",
			wantContentLen: 0,
		},
		{
			name:          "malformed_request_line",
			raw:           []byte("INVALID\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "",
			wantHost:      "",
			wantPath:      "",
			wantContentLen: 0,
		},
		{
			name:          "invalid_content_length",
			raw:           []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: abc\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:          "binary_garbage",
			raw:           []byte{0x00, 0xff, 0xfe, 0x80, 0x90, 0xa0},
			wantMethod:    "",
			wantHost:      "",
			wantPath:      "",
			wantContentLen: 0,
		},
		{
			name:          "partial_request",
			raw:           []byte("GET /bucket"),
			wantMethod:    "GET",
			wantHost:      "",
			wantPath:      "/bucket",
			wantContentLen: 0,
		},
		{
			name:          "multiple_colons_in_header_value",
			raw:           []byte("GET / HTTP/1.1\r\nHost: [::1]:9000\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "[::1]:9000",
			wantPath:      "/",
			wantContentLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, host, path, contentLen := ParseHTTPRequest(tt.raw)
			assert.Equal(t, tt.wantMethod, method, "method mismatch")
			assert.Equal(t, tt.wantHost, host, "host mismatch")
			assert.Equal(t, tt.wantPath, path, "path mismatch")
			assert.Equal(t, tt.wantContentLen, contentLen, "content-length mismatch")
		})
	}
}

// TestParseHTTPRequest_UTF8Path tests UTF-8 path handling.
func TestParseHTTPRequest_UTF8Path(t *testing.T) {
	raw := []byte("GET /bucket/ключ HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n")
	method, _, path, _ := ParseHTTPRequest(raw)

	assert.Equal(t, "GET", method)
	assert.Contains(t, path, "ключ")
}

// TestParseHTTPResponse tests the ParseHTTPResponse function.
func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name       string
		raw        []byte
		wantStatus int
	}{
		// Valid responses
		{name: "200_ok", raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"), wantStatus: 200},
		{name: "201_created", raw: []byte("HTTP/1.1 201 Created\r\n\r\n"), wantStatus: 201},
		{name: "204_no_content", raw: []byte("HTTP/1.1 204 No Content\r\n\r\n"), wantStatus: 204},
		{name: "304_not_modified", raw: []byte("HTTP/1.1 304 Not Modified\r\n\r\n"), wantStatus: 304},
		{name: "400_bad_request", raw: []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), wantStatus: 400},
		{name: "403_forbidden", raw: []byte("HTTP/1.1 403 Forbidden\r\n\r\n"), wantStatus: 403},
		{name: "404_not_found", raw: []byte("HTTP/1.1 404 Not Found\r\n\r\n"), wantStatus: 404},
		{name: "500_internal_server_error", raw: []byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"), wantStatus: 500},
		{name: "503_service_unavailable", raw: []byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"), wantStatus: 503},
		{name: "100_continue", raw: []byte("HTTP/1.1 100 Continue\r\n\r\n"), wantStatus: 100},
		{name: "http_10_response", raw: []byte("HTTP/1.0 200 OK\r\n\r\n"), wantStatus: 200},

		// Error cases
		{name: "empty_input", raw: []byte(""), wantStatus: 0},
		{name: "non_http_response", raw: []byte("This is not an HTTP response"), wantStatus: 0},
		{name: "malformed_status_code", raw: []byte("HTTP/1.1 ABC OK\r\n\r\n"), wantStatus: 0},
		{name: "missing_status_code", raw: []byte("HTTP/1.1\r\n\r\n"), wantStatus: 0},
		{name: "binary_garbage", raw: []byte{0x00, 0xff, 0xfe, 0x80, 0x90, 0xa0}, wantStatus: 0},
		{name: "partial_response", raw: []byte("HTTP/1.1 20"), wantStatus: 20},
		{name: "truncated_http_prefix", raw: []byte("HTTP"), wantStatus: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ParseHTTPResponse(tt.raw)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}

// TestParseBucketEndpoint tests the ParseBucketEndpoint function.
func TestParseBucketEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		path         string
		wantBucket   string
		wantEndpoint string
	}{
		// Path-style URLs
		{
			name:         "path_style_simple",
			host:         "s3.amazonaws.com",
			path:         "/mybucket/mykey.txt",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "path_style_nested_key",
			host:         "s3.amazonaws.com",
			path:         "/bucket/dir/subdir/key.txt",
			wantBucket:   "bucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "path_style_bucket_only",
			host:         "s3.amazonaws.com",
			path:         "/mybucket",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "path_style_with_query_string",
			host:         "s3.amazonaws.com",
			path:         "/mybucket/mykey?uploadId=abc123",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},

		// Virtual-host style (used only for root path)
		{
			name:         "virtual_host_style_root_path",
			host:         "mybucket.s3.amazonaws.com",
			path:         "/",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "virtual_host_style_regional",
			host:         "mybucket.s3.us-west-2.amazonaws.com",
			path:         "/",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.us-west-2.amazonaws.com",
		},
		{
			name:         "virtual_host_style_minio",
			host:         "mybucket.minio.local",
			path:         "/",
			wantBucket:   "mybucket",
			wantEndpoint: "minio.local",
		},

		// Path-style takes precedence
		{
			name:         "path_style_takes_precedence",
			host:         "mybucket.s3.amazonaws.com",
			path:         "/otherbucket/key",
			wantBucket:   "otherbucket",
			wantEndpoint: "mybucket.s3.amazonaws.com",
		},

		// Edge cases
		{
			name:         "empty_host_and_path",
			host:         "",
			path:         "",
			wantBucket:   "",
			wantEndpoint: "",
		},
		{
			name:         "simple_host_no_subdomain",
			host:         "localhost",
			path:         "/mybucket/key",
			wantBucket:   "mybucket",
			wantEndpoint: "localhost",
		},
		{
			name:         "host_with_port",
			host:         "localhost:9000",
			path:         "/mybucket/key",
			wantBucket:   "mybucket",
			wantEndpoint: "localhost:9000",
		},
		{
			name:         "list_operation_path",
			host:         "s3.amazonaws.com",
			path:         "/mybucket?list-type=2&prefix=myprefix/",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "multipart_upload_path",
			host:         "s3.amazonaws.com",
			path:         "/mybucket/mykey?uploads",
			wantBucket:   "mybucket",
			wantEndpoint: "s3.amazonaws.com",
		},
		{
			name:         "ipv4_host",
			host:         "192.168.1.100",
			path:         "/mybucket/key",
			wantBucket:   "mybucket",
			wantEndpoint: "192.168.1.100",
		},
		{
			name:         "ipv6_host",
			host:         "[::1]",
			path:         "/mybucket/key",
			wantBucket:   "mybucket",
			wantEndpoint: "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, endpoint := ParseBucketEndpoint(tt.host, tt.path)
			assert.Equal(t, tt.wantBucket, bucket, "bucket mismatch")
			assert.Equal(t, tt.wantEndpoint, endpoint, "endpoint mismatch")
		})
	}
}

// TestParseBucketEndpoint_Unicode tests Unicode bucket name handling.
func TestParseBucketEndpoint_Unicode(t *testing.T) {
	bucket, endpoint := ParseBucketEndpoint("s3.amazonaws.com", "/тест/key")
	assert.Equal(t, "тест", bucket)
	assert.Equal(t, "s3.amazonaws.com", endpoint)
}

// TestIsS3Method tests the IsS3Method function.
func TestIsS3Method(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"GET", true},
		{"PUT", true},
		{"POST", true},
		{"DELETE", true},
		{"HEAD", true},
		{"PATCH", false},
		{"OPTIONS", false},
		{"CONNECT", false},
		{"", false},
		{"get", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			assert.Equal(t, tt.want, IsS3Method(tt.method))
		})
	}
}

// TestDetectS3Operation tests the DetectS3Operation function.
func TestDetectS3Operation(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   S3Operation
	}{
		// GET operations
		{name: "get_object", method: "GET", path: "/bucket/key", want: OpGetObject},
		{name: "list_prefix", method: "GET", path: "/bucket?list-type=2&prefix=foo/", want: OpListPrefix},
		{name: "list_objects", method: "GET", path: "/bucket/", want: OpListObjects},

		// PUT operations
		{name: "put_object", method: "PUT", path: "/bucket/key", want: OpPutObject},
		{name: "mpu_part", method: "PUT", path: "/bucket/key?partNumber=1&uploadId=abc", want: OpMPUPart},
		{name: "create_bucket", method: "PUT", path: "/bucket", want: OpCreateBucket},

		// POST operations
		{name: "mpu_create", method: "POST", path: "/bucket/key?uploads", want: OpMPUCreate},
		{name: "mpu_complete", method: "POST", path: "/bucket/key?uploadId=abc", want: OpMPUComplete},

		// DELETE operations
		{name: "delete_object", method: "DELETE", path: "/bucket/key", want: OpDeleteObject},
		{name: "mpu_abort", method: "DELETE", path: "/bucket/key?uploadId=abc", want: OpMPUAbort},
		{name: "delete_bucket", method: "DELETE", path: "/bucket", want: OpDeleteBucket},

		// HEAD operations
		{name: "head_object", method: "HEAD", path: "/bucket/key", want: OpHeadObject},
		{name: "head_bucket", method: "HEAD", path: "/bucket", want: OpHeadBucket},

		// Unknown
		{name: "unknown_method", method: "PATCH", path: "/bucket/key", want: OpUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := DetectS3Operation(tt.method, tt.path)
			assert.Equal(t, tt.want, op)
		})
	}
}
