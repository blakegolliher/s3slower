// Package http provides HTTP request/response parsing for S3 traffic.
package http

import (
	"bytes"
	"strconv"
	"strings"
)

// ParseHTTPRequest parses a raw HTTP request and extracts method, host, path, and content-length.
// Returns empty strings and 0 for invalid or empty input.
func ParseHTTPRequest(raw []byte) (method, host, path string, contentLength int) {
	if len(raw) == 0 {
		return "", "", "", 0
	}

	// Try to decode as UTF-8, handling errors gracefully
	text := string(raw)

	// Split into lines
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		return "", "", "", 0
	}

	// Parse request line
	requestLine := lines[0]
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		// Need at least method and path
		return "", "", "", 0
	}

	method = parts[0]
	path = parts[1]

	// Parse headers (case-insensitive)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
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
			host = headerValue
		case "content-length":
			if cl, err := strconv.Atoi(headerValue); err == nil {
				contentLength = cl
			}
		}
	}

	return method, host, path, contentLength
}

// ParseHTTPResponse parses a raw HTTP response and extracts the status code.
// Returns 0 for invalid or empty input.
func ParseHTTPResponse(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}

	// Check for HTTP prefix
	if !bytes.HasPrefix(raw, []byte("HTTP/")) {
		return 0
	}

	// Find first space after HTTP version
	spaceIdx := bytes.IndexByte(raw[5:], ' ')
	if spaceIdx == -1 {
		return 0
	}

	// Find the status code (next word after version)
	start := 5 + spaceIdx + 1
	if start >= len(raw) {
		return 0
	}

	// Extract status code (up to next space or end)
	end := start
	for end < len(raw) && raw[end] >= '0' && raw[end] <= '9' {
		end++
	}

	if end == start {
		return 0
	}

	statusCode, err := strconv.Atoi(string(raw[start:end]))
	if err != nil {
		return 0
	}

	return statusCode
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
	if strings.Contains(host, ".") {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}

	return "", host
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

// IsS3Method checks if a method is valid for S3 operations.
func IsS3Method(method string) bool {
	switch HTTPMethod(method) {
	case MethodGET, MethodPUT, MethodPOST, MethodDELETE, MethodHEAD:
		return true
	}
	return false
}

// S3Operation represents an S3 operation type.
type S3Operation string

const (
	OpGetObject      S3Operation = "GET_OBJECT"
	OpPutObject      S3Operation = "PUT_OBJECT"
	OpDeleteObject   S3Operation = "DELETE_OBJECT"
	OpHeadObject     S3Operation = "HEAD_OBJECT"
	OpListObjects    S3Operation = "LIST_OBJECTS"
	OpListPrefix     S3Operation = "LIST_PREFIX"
	OpMPUCreate      S3Operation = "MPU_CREATE"
	OpMPUPart        S3Operation = "MPU_PART"
	OpMPUComplete    S3Operation = "MPU_COMPLETE"
	OpMPUAbort       S3Operation = "MPU_ABORT"
	OpCreateBucket   S3Operation = "CREATE_BUCKET"
	OpDeleteBucket   S3Operation = "DELETE_BUCKET"
	OpHeadBucket     S3Operation = "HEAD_BUCKET"
	OpUnknown        S3Operation = "UNKNOWN"
)

// DetectS3Operation determines the S3 operation from method and path.
func DetectS3Operation(method, path string) S3Operation {
	pathLower := strings.ToLower(path)

	switch HTTPMethod(method) {
	case MethodGET:
		if strings.Contains(pathLower, "list-type=") || strings.Contains(pathLower, "prefix=") {
			return OpListPrefix
		}
		if strings.HasSuffix(path, "/") || path == "" {
			return OpListObjects
		}
		return OpGetObject

	case MethodPUT:
		if strings.Contains(pathLower, "partnumber=") {
			return OpMPUPart
		}
		// Check if this is a bucket-only path (no key)
		pathPart := path
		if idx := strings.Index(path, "?"); idx != -1 {
			pathPart = path[:idx]
		}
		parts := strings.Split(strings.Trim(pathPart, "/"), "/")
		if len(parts) == 1 && parts[0] != "" {
			return OpCreateBucket
		}
		return OpPutObject

	case MethodPOST:
		if strings.Contains(pathLower, "?uploads") {
			return OpMPUCreate
		}
		if strings.Contains(pathLower, "uploadid=") && !strings.Contains(pathLower, "partnumber=") {
			return OpMPUComplete
		}
		return OpUnknown

	case MethodDELETE:
		if strings.Contains(pathLower, "uploadid=") {
			return OpMPUAbort
		}
		pathPart := path
		if idx := strings.Index(path, "?"); idx != -1 {
			pathPart = path[:idx]
		}
		parts := strings.Split(strings.Trim(pathPart, "/"), "/")
		if len(parts) == 1 && parts[0] != "" {
			return OpDeleteBucket
		}
		return OpDeleteObject

	case MethodHEAD:
		pathPart := path
		if idx := strings.Index(path, "?"); idx != -1 {
			pathPart = path[:idx]
		}
		parts := strings.Split(strings.Trim(pathPart, "/"), "/")
		if len(parts) == 1 && parts[0] != "" {
			return OpHeadBucket
		}
		return OpHeadObject
	}

	return OpUnknown
}
