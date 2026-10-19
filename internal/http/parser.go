// Package http provides HTTP request/response parsing for S3 traffic.
package http

import (
	"bytes"
	"net"
	"strconv"
	"strings"
)

// Request holds the parts of an HTTP request head that s3slower uses.
type Request struct {
	Method string
	Host   string
	Path   string

	// ContentLength is the request body size. For aws-chunked uploads it
	// is x-amz-decoded-content-length (the object size), not the encoded
	// wire size. Only meaningful when HasContentLength is set.
	ContentLength    int
	HasContentLength bool

	// HeadersComplete reports whether the blank line ending the header
	// block was seen. The BPF capture is truncated, so a missing header
	// in an incomplete block may simply not have been captured.
	HeadersComplete bool

	// Range is the Range header value (e.g. "bytes=0-65535"), if any.
	Range string

	// CopySource is set when x-amz-copy-source is present (CopyObject,
	// UploadPartCopy): the request carries no body.
	CopySource bool
}

// ParseRequest parses a raw (possibly truncated) HTTP request head.
// Returns a zero Request for invalid or empty input.
func ParseRequest(raw []byte) Request {
	var r Request
	if len(raw) == 0 {
		return r
	}

	lines := strings.Split(string(raw), "\r\n")

	// Request line: METHOD PATH VERSION
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return Request{}
	}
	r.Method = parts[0]
	r.Path = parts[1]

	decodedLength := -1
	for _, line := range lines[1:] {
		if line == "" {
			r.HeadersComplete = true
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		headerName := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		headerValue := strings.TrimSpace(line[colonIdx+1:])

		switch headerName {
		case "host":
			r.Host = headerValue
		case "content-length":
			if cl, err := strconv.Atoi(headerValue); err == nil {
				r.ContentLength = cl
				r.HasContentLength = true
			}
		case "x-amz-decoded-content-length":
			if cl, err := strconv.Atoi(headerValue); err == nil {
				decodedLength = cl
			}
		case "range":
			r.Range = headerValue
		case "x-amz-copy-source":
			r.CopySource = true
		}
	}

	// The decoded length wins regardless of header order.
	if decodedLength >= 0 {
		r.ContentLength = decodedLength
		r.HasContentLength = true
	}

	return r
}

// Response holds the parts of an HTTP response head that s3slower uses.
type Response struct {
	StatusCode       int
	ContentLength    int
	HasContentLength bool

	// HeaderLen is the length of the header block including the final
	// blank line, or 0 if the end of the block was not captured.
	HeaderLen int
}

// ParseResponse parses a raw (possibly truncated) HTTP response head.
// Returns a zero Response for invalid or empty input.
func ParseResponse(raw []byte) Response {
	var r Response
	if !bytes.HasPrefix(raw, []byte("HTTP/")) {
		return r
	}

	// Status code is the run of digits after the first space.
	spaceIdx := bytes.IndexByte(raw[5:], ' ')
	if spaceIdx == -1 {
		return r
	}
	start := 5 + spaceIdx + 1
	end := start
	for end < len(raw) && raw[end] >= '0' && raw[end] <= '9' {
		end++
	}
	sc, err := strconv.Atoi(string(raw[start:end]))
	if err != nil {
		return r
	}
	r.StatusCode = sc

	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx != -1 {
		r.HeaderLen = idx + 4
		// A 1xx interim head followed by the final response in the same
		// read: report the final response.
		if sc >= 100 && sc < 200 && bytes.HasPrefix(raw[r.HeaderLen:], []byte("HTTP/")) {
			final := ParseResponse(raw[r.HeaderLen:])
			if final.HeaderLen > 0 {
				final.HeaderLen += r.HeaderLen
			}
			return final
		}
	}

	lines := strings.Split(string(raw), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:colonIdx]), "content-length") {
			if cl, err := strconv.Atoi(strings.TrimSpace(line[colonIdx+1:])); err == nil {
				r.ContentLength = cl
				r.HasContentLength = true
			}
		}
	}

	return r
}

// ParseBucketEndpoint extracts bucket and endpoint from host and path.
// Handles both path-style and virtual-host-style URLs.
func ParseBucketEndpoint(host, path string) (bucket, endpoint string) {
	if host == "" && path == "" {
		return "", ""
	}

	// Strip query string from path
	pathPart := path
	if idx := strings.Index(path, "?"); idx != -1 {
		pathPart = path[:idx]
	}

	// Try path-style first: /bucket/key
	if pathPart != "" && pathPart != "/" {
		parts := strings.SplitN(strings.TrimPrefix(pathPart, "/"), "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0], host
		}
	}

	// Virtual-host-style: bucket.s3.amazonaws.com or bucket.endpoint
	// Only used when path doesn't contain a bucket
	// Skip if host is an IP address
	if strings.Contains(host, ".") && !IsIPAddress(host) {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}

	return "", host
}

// IsIPAddress checks if the given string is an IP address (IPv4 or IPv6),
// with or without a port suffix (e.g. "1.2.3.4:9000", "[::1]:9000").
func IsIPAddress(s string) bool {
	// Try stripping port via net.SplitHostPort (handles IPv6 brackets)
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host) != nil
	}
	// No port — try parsing directly (also strips brackets if present)
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}

// IsLikelyS3Traffic checks whether raw HTTP request data contains AWS S3
// signature headers (x-amz-*), indicating this is S3 traffic rather than
// unrelated HTTP traffic (e.g., Prometheus scrapes, Grafana queries).
func IsLikelyS3Traffic(data []byte) bool {
	lower := bytes.ToLower(data)
	return bytes.Contains(lower, []byte("x-amz-")) ||
		bytes.Contains(lower, []byte("aws4-hmac-sha256"))
}

// HTTPMethod represents an HTTP method.
type HTTPMethod string

const (
	MethodGET    HTTPMethod = "GET"
	MethodPUT    HTTPMethod = "PUT"
	MethodPOST   HTTPMethod = "POST"
	MethodDELETE HTTPMethod = "DELETE"
	MethodHEAD   HTTPMethod = "HEAD"
)

// S3Operation represents an S3 operation type.
type S3Operation string

const (
	OpGetObject      S3Operation = "GET_OBJECT"
	OpGetObjectRange S3Operation = "GET_OBJECT_RANGE"
	OpPutObject      S3Operation = "PUT_OBJECT"
	OpCopyObject     S3Operation = "COPY_OBJECT"
	OpDeleteObject   S3Operation = "DELETE_OBJECT"
	OpDeleteObjects  S3Operation = "DELETE_OBJECTS"
	OpHeadObject     S3Operation = "HEAD_OBJECT"
	OpListObjects    S3Operation = "LIST_OBJECTS"
	OpListPrefix     S3Operation = "LIST_PREFIX"
	OpListBuckets    S3Operation = "LIST_BUCKETS"
	OpMPUCreate      S3Operation = "MPU_CREATE"
	OpMPUPart        S3Operation = "MPU_PART"
	OpMPUComplete    S3Operation = "MPU_COMPLETE"
	OpMPUAbort       S3Operation = "MPU_ABORT"
	OpMPUList        S3Operation = "MPU_LIST"
	OpMPUListParts   S3Operation = "MPU_LIST_PARTS"
	OpCreateBucket   S3Operation = "CREATE_BUCKET"
	OpDeleteBucket   S3Operation = "DELETE_BUCKET"
	OpHeadBucket     S3Operation = "HEAD_BUCKET"
	OpBucketConfig   S3Operation = "BUCKET_CONFIG"
	OpUnknown        S3Operation = "UNKNOWN"
)

// listParams are query parameters that mark a bucket GET as a listing
// (ListObjects v1/v2, ListObjectVersions) rather than a bucket
// sub-resource read such as ?location or ?versioning.
var listParams = []string{
	"list-type", "prefix", "delimiter", "marker", "max-keys", "encoding-type",
	"continuation-token", "start-after", "fetch-owner", "versions",
}

// splitPath splits a request target into its path and the set of
// (lowercased) query parameter names.
func splitPath(target string) (path string, params map[string]bool) {
	path = target
	params = map[string]bool{}
	idx := strings.Index(target, "?")
	if idx == -1 {
		return path, params
	}
	path = target[:idx]
	for _, kv := range strings.Split(target[idx+1:], "&") {
		if kv == "" {
			continue
		}
		if eq := strings.Index(kv, "="); eq != -1 {
			kv = kv[:eq]
		}
		params[strings.ToLower(kv)] = true
	}
	return path, params
}

// isBucketOnlyPath returns true if the path contains only a bucket name
// (single path segment with no key). The query string must already be
// stripped.
func isBucketOnlyPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 1 && parts[0] != ""
}

// DetectS3Operation determines the S3 operation from method and path,
// assuming path-style addressing (/bucket/key).
func DetectS3Operation(method, target string) S3Operation {
	path, params := splitPath(target)
	root := path == "" || path == "/"
	bucketOnly := isBucketOnlyPath(path)

	switch HTTPMethod(method) {
	case MethodGET:
		switch {
		case params["list-type"]:
			return OpListPrefix
		case root:
			// Path-style: a GET of / lists buckets, whatever its
			// parameters (max-buckets, continuation-token, prefix, x-id).
			return OpListBuckets
		case params["uploads"]:
			return OpMPUList
		case params["uploadid"]:
			return OpMPUListParts
		case params["prefix"]:
			return OpListPrefix
		case bucketOnly || strings.HasSuffix(path, "/"):
			if len(params) == 0 || hasAny(params, listParams) {
				return OpListObjects
			}
			return OpBucketConfig
		}
		return OpGetObject

	case MethodPUT:
		if params["partnumber"] {
			return OpMPUPart
		}
		if bucketOnly {
			if len(params) == 0 {
				return OpCreateBucket
			}
			return OpBucketConfig
		}
		return OpPutObject

	case MethodPOST:
		switch {
		case params["uploads"]:
			return OpMPUCreate
		case params["uploadid"]:
			return OpMPUComplete
		case params["delete"]:
			return OpDeleteObjects
		}
		return OpUnknown

	case MethodDELETE:
		if params["uploadid"] {
			return OpMPUAbort
		}
		if bucketOnly {
			if len(params) == 0 {
				return OpDeleteBucket
			}
			return OpBucketConfig
		}
		return OpDeleteObject

	case MethodHEAD:
		if bucketOnly {
			return OpHeadBucket
		}
		return OpHeadObject
	}

	return OpUnknown
}

// ClassifyRequest refines DetectS3Operation with header information:
// a GET with a Range header is a ranged read, and a PUT carrying
// x-amz-copy-source is a server-side copy.
func ClassifyRequest(r Request) S3Operation {
	op := DetectS3Operation(r.Method, r.Path)
	switch {
	case op == OpGetObject && r.Range != "":
		return OpGetObjectRange
	case op == OpPutObject && r.CopySource:
		return OpCopyObject
	}
	return op
}

func hasAny(params map[string]bool, names []string) bool {
	for _, n := range names {
		if params[n] {
			return true
		}
	}
	return false
}
