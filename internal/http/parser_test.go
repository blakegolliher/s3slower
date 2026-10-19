// Package http provides HTTP request/response parsing tests.
package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseRequest tests the basic fields returned by ParseRequest.
func TestParseRequest(t *testing.T) {
	tests := []struct {
		name           string
		raw            []byte
		wantMethod     string
		wantHost       string
		wantPath       string
		wantContentLen int
	}{
		// Valid requests
		{
			name:           "valid_get_request",
			raw:            []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 0\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:           "valid_put_request_with_content_length",
			raw:            []byte("PUT /mybucket/mykey.txt HTTP/1.1\r\nHost: minio.local:9000\r\nContent-Length: 1048576\r\n\r\n"),
			wantMethod:     "PUT",
			wantHost:       "minio.local:9000",
			wantPath:       "/mybucket/mykey.txt",
			wantContentLen: 1048576,
		},
		{
			name:           "valid_post_request",
			raw:            []byte("POST /bucket/key?uploads HTTP/1.1\r\nHost: s3.us-west-2.amazonaws.com\r\n\r\n"),
			wantMethod:     "POST",
			wantHost:       "s3.us-west-2.amazonaws.com",
			wantPath:       "/bucket/key?uploads",
			wantContentLen: 0,
		},
		{
			name:           "valid_delete_request",
			raw:            []byte("DELETE /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:     "DELETE",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:           "valid_head_request",
			raw:            []byte("HEAD /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:     "HEAD",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 0,
		},

		// Missing headers
		{
			name:           "missing_host_header",
			raw:            []byte("GET /bucket/key HTTP/1.1\r\nContent-Length: 100\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "",
			wantPath:       "/bucket/key",
			wantContentLen: 100,
		},
		{
			name:           "missing_content_length",
			raw:            []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 0,
		},

		// Case insensitivity
		{
			name:           "case_insensitive_headers",
			raw:            []byte("GET /bucket/key HTTP/1.1\r\nhOsT: s3.amazonaws.com\r\ncontent-LENGTH: 512\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 512,
		},

		// Edge cases
		{
			name:           "empty_input",
			raw:            []byte(""),
			wantMethod:     "",
			wantHost:       "",
			wantPath:       "",
			wantContentLen: 0,
		},
		{
			name:           "malformed_request_line",
			raw:            []byte("INVALID\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:     "",
			wantHost:       "",
			wantPath:       "",
			wantContentLen: 0,
		},
		{
			name:           "invalid_content_length",
			raw:            []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: abc\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "s3.amazonaws.com",
			wantPath:       "/bucket/key",
			wantContentLen: 0,
		},
		{
			name:           "binary_garbage",
			raw:            []byte{0x00, 0xff, 0xfe, 0x80, 0x90, 0xa0},
			wantMethod:     "",
			wantHost:       "",
			wantPath:       "",
			wantContentLen: 0,
		},
		{
			name:           "partial_request",
			raw:            []byte("GET /bucket"),
			wantMethod:     "GET",
			wantHost:       "",
			wantPath:       "/bucket",
			wantContentLen: 0,
		},
		{
			name:           "multiple_colons_in_header_value",
			raw:            []byte("GET / HTTP/1.1\r\nHost: [::1]:9000\r\n\r\n"),
			wantMethod:     "GET",
			wantHost:       "[::1]:9000",
			wantPath:       "/",
			wantContentLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ParseRequest(tt.raw)
			assert.Equal(t, tt.wantMethod, r.Method, "method mismatch")
			assert.Equal(t, tt.wantHost, r.Host, "host mismatch")
			assert.Equal(t, tt.wantPath, r.Path, "path mismatch")
			assert.Equal(t, tt.wantContentLen, r.ContentLength, "content-length mismatch")
		})
	}
}

// TestParseRequest_UTF8Path tests UTF-8 path handling.
func TestParseRequest_UTF8Path(t *testing.T) {
	raw := []byte("GET /bucket/ключ HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n")
	r := ParseRequest(raw)

	assert.Equal(t, "GET", r.Method)
	assert.Contains(t, r.Path, "ключ")
}

// TestParseRequest_Headers tests the header-derived fields used for
// operation refinement and byte accounting.
func TestParseRequest_Headers(t *testing.T) {
	t.Run("range_header", func(t *testing.T) {
		r := ParseRequest([]byte("GET /b/k HTTP/1.1\r\nHost: h\r\nRange: bytes=0-65535\r\n\r\n"))
		assert.Equal(t, "bytes=0-65535", r.Range)
		assert.False(t, r.HasContentLength)
		assert.True(t, r.HeadersComplete)
	})
	t.Run("copy_source", func(t *testing.T) {
		r := ParseRequest([]byte("PUT /b/dst HTTP/1.1\r\nx-amz-copy-source: /b/src\r\nContent-Length: 0\r\n\r\n"))
		assert.True(t, r.CopySource)
		assert.True(t, r.HasContentLength)
		assert.Equal(t, 0, r.ContentLength)
	})
	t.Run("decoded_length_wins_regardless_of_order", func(t *testing.T) {
		r := ParseRequest([]byte("PUT /b/k HTTP/1.1\r\nX-Amz-Decoded-Content-Length: 1000\r\nContent-Length: 1100\r\n\r\n"))
		assert.Equal(t, 1000, r.ContentLength)
		assert.True(t, r.HasContentLength)
	})
	t.Run("truncated_head", func(t *testing.T) {
		r := ParseRequest([]byte("PUT /b/k HTTP/1.1\r\nHost: h\r\nAuthorization: AWS4-HMAC-SHA256 Cred"))
		assert.False(t, r.HeadersComplete)
		assert.False(t, r.HasContentLength)
	})
}

// TestParseResponse tests status and Content-Length parsing.
func TestParseResponse(t *testing.T) {
	tests := []struct {
		name              string
		raw               []byte
		wantStatus        int
		wantContentLength int
	}{
		// Valid responses
		{name: "200_ok_with_cl", raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"), wantStatus: 200, wantContentLength: 1024},
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
		{name: "200_large_cl", raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 10240\r\nContent-Type: binary/octet-stream\r\n\r\n"), wantStatus: 200, wantContentLength: 10240},

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
			r := ParseResponse(tt.raw)
			assert.Equal(t, tt.wantStatus, r.StatusCode)
			assert.Equal(t, tt.wantContentLength, r.ContentLength)
		})
	}
}

// TestParseResponse_HeaderLen tests header-block detection used to
// separate body bytes from header bytes.
func TestParseResponse_HeaderLen(t *testing.T) {
	head := "HTTP/1.1 204 No Content\r\nx-amz-request-id: 1\r\n\r\n"
	r := ParseResponse([]byte(head + "trailing"))
	assert.Equal(t, len(head), r.HeaderLen)
	assert.False(t, r.HasContentLength)

	r = ParseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	assert.True(t, r.HasContentLength)
	assert.Equal(t, 0, r.ContentLength)

	r = ParseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: x"))
	assert.Equal(t, 0, r.HeaderLen, "truncated head has no known header length")
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
		{name: "list_objects_no_slash", method: "GET", path: "/bucket", want: OpListObjects},
		{name: "list_objects_v1_params", method: "GET", path: "/bucket?delimiter=%2F&encoding-type=url", want: OpListObjects},
		{name: "list_object_versions", method: "GET", path: "/bucket?versions", want: OpListObjects},
		{name: "list_buckets", method: "GET", path: "/", want: OpListBuckets},
		{name: "list_buckets_paged", method: "GET", path: "/?max-buckets=100", want: OpListBuckets},
		{name: "list_buckets_continuation", method: "GET", path: "/?continuation-token=abc", want: OpListBuckets},
		{name: "list_buckets_prefix", method: "GET", path: "/?prefix=team-", want: OpListBuckets},
		{name: "list_buckets_go_sdk", method: "GET", path: "/?x-id=ListBuckets", want: OpListBuckets},
		{name: "list_vhost_v2", method: "GET", path: "/?list-type=2&prefix=a%2F", want: OpListPrefix},
		{name: "mpu_list", method: "GET", path: "/bucket?uploads", want: OpMPUList},
		{name: "mpu_list_parts", method: "GET", path: "/bucket/key?uploadId=abc", want: OpMPUListParts},
		{name: "bucket_location", method: "GET", path: "/bucket?location", want: OpBucketConfig},
		{name: "get_object_with_query", method: "GET", path: "/bucket/key?versionId=3", want: OpGetObject},

		// PUT operations
		{name: "put_object", method: "PUT", path: "/bucket/key", want: OpPutObject},
		{name: "mpu_part", method: "PUT", path: "/bucket/key?partNumber=1&uploadId=abc", want: OpMPUPart},
		{name: "create_bucket", method: "PUT", path: "/bucket", want: OpCreateBucket},
		{name: "put_bucket_versioning", method: "PUT", path: "/bucket?versioning", want: OpBucketConfig},

		// POST operations
		{name: "mpu_create", method: "POST", path: "/bucket/key?uploads", want: OpMPUCreate},
		{name: "mpu_complete", method: "POST", path: "/bucket/key?uploadId=abc", want: OpMPUComplete},
		{name: "delete_objects", method: "POST", path: "/bucket?delete", want: OpDeleteObjects},
		{name: "delete_objects_empty_value", method: "POST", path: "/bucket?delete=", want: OpDeleteObjects},
		{name: "unknown_post", method: "POST", path: "/v1/metrics", want: OpUnknown},

		// DELETE operations
		{name: "delete_object", method: "DELETE", path: "/bucket/key", want: OpDeleteObject},
		{name: "mpu_abort", method: "DELETE", path: "/bucket/key?uploadId=abc", want: OpMPUAbort},
		{name: "delete_bucket", method: "DELETE", path: "/bucket", want: OpDeleteBucket},
		{name: "delete_bucket_policy", method: "DELETE", path: "/bucket?policy", want: OpBucketConfig},

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

// TestClassifyRequest tests header-based refinement of the operation.
func TestClassifyRequest(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want S3Operation
	}{
		{"ranged_get", "GET /b/k HTTP/1.1\r\nRange: bytes=100-199\r\n\r\n", OpGetObjectRange},
		{"suffix_range_get", "GET /b/k HTTP/1.1\r\nRange: bytes=-8192\r\n\r\n", OpGetObjectRange},
		{"full_get", "GET /b/k HTTP/1.1\r\nHost: h\r\n\r\n", OpGetObject},
		{"copy_object", "PUT /b/dst HTTP/1.1\r\nX-Amz-Copy-Source: b/src\r\n\r\n", OpCopyObject},
		{"upload_part_copy_stays_part", "PUT /b/k?partNumber=2&uploadId=x HTTP/1.1\r\nX-Amz-Copy-Source: b/src\r\n\r\n", OpMPUPart},
		{"plain_put", "PUT /b/k HTTP/1.1\r\nContent-Length: 5\r\n\r\n", OpPutObject},
		{"range_on_list_ignored", "GET /b?list-type=2 HTTP/1.1\r\nRange: bytes=0-1\r\n\r\n", OpListPrefix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifyRequest(ParseRequest([]byte(tt.raw))))
		})
	}
}

// TestParseResponse_InterimThenFinal tests a 1xx head and the final
// response arriving in one read.
func TestParseResponse_InterimThenFinal(t *testing.T) {
	interim := "HTTP/1.1 100 Continue\r\n\r\n"
	final := "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"
	r := ParseResponse([]byte(interim + final + "payload"))
	assert.Equal(t, 200, r.StatusCode)
	assert.Equal(t, 7, r.ContentLength)
	assert.Equal(t, len(interim)+len(final), r.HeaderLen)

	r = ParseResponse([]byte(interim))
	assert.Equal(t, 100, r.StatusCode, "a lone interim head is still reported as such")
}
