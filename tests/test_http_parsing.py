"""
Tests for HTTP parsing functions in s3slower.core.

These functions parse HTTP request/response headers and extract
S3-relevant information like bucket names and endpoints.
"""

from __future__ import annotations

import pytest

from s3slower.core import parse_bucket_endpoint, parse_http_request, parse_http_response


class TestParseHttpRequest:
    """Tests for parse_http_request function."""

    def test_valid_get_request(self) -> None:
        """Parse a valid GET request with Host and Content-Length headers."""
        raw = b"GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 0\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "GET"
        assert host == "s3.amazonaws.com"
        assert path == "/bucket/key"
        assert content_length == 0

    def test_valid_put_request_with_content_length(self) -> None:
        """Parse a PUT request with a non-zero Content-Length."""
        raw = b"PUT /mybucket/mykey.txt HTTP/1.1\r\nHost: minio.local:9000\r\nContent-Length: 1048576\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "PUT"
        assert host == "minio.local:9000"
        assert path == "/mybucket/mykey.txt"
        assert content_length == 1048576

    def test_valid_post_request(self) -> None:
        """Parse a POST request (used for multipart uploads)."""
        raw = b"POST /bucket/key?uploads HTTP/1.1\r\nHost: s3.us-west-2.amazonaws.com\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "POST"
        assert host == "s3.us-west-2.amazonaws.com"
        assert path == "/bucket/key?uploads"
        assert content_length == 0

    def test_valid_delete_request(self) -> None:
        """Parse a DELETE request."""
        raw = b"DELETE /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "DELETE"
        assert host == "s3.amazonaws.com"
        assert path == "/bucket/key"
        assert content_length == 0

    def test_valid_head_request(self) -> None:
        """Parse a HEAD request."""
        raw = b"HEAD /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "HEAD"
        assert host == "s3.amazonaws.com"
        assert path == "/bucket/key"

    def test_missing_host_header(self) -> None:
        """Request without Host header should return empty host."""
        raw = b"GET /bucket/key HTTP/1.1\r\nContent-Length: 100\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "GET"
        assert host == ""
        assert path == "/bucket/key"
        assert content_length == 100

    def test_missing_content_length(self) -> None:
        """Request without Content-Length should return 0."""
        raw = b"GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "GET"
        assert content_length == 0

    def test_case_insensitive_headers(self) -> None:
        """Headers should be parsed case-insensitively."""
        raw = b"GET /bucket/key HTTP/1.1\r\nhOsT: s3.amazonaws.com\r\ncontent-LENGTH: 512\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert host == "s3.amazonaws.com"
        assert content_length == 512

    def test_empty_input(self) -> None:
        """Empty input should return empty values."""
        method, host, path, content_length = parse_http_request(b"")

        assert method == ""
        assert host == ""
        assert path == ""
        assert content_length == 0

    def test_malformed_request_line(self) -> None:
        """Malformed request line with single word returns empty for both."""
        raw = b"INVALID\r\nHost: s3.amazonaws.com\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        # Single word without path/version returns empty (not a valid HTTP request)
        assert method == ""
        assert path == ""

    def test_invalid_content_length(self) -> None:
        """Non-numeric Content-Length should return 0."""
        raw = b"GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: abc\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert content_length == 0

    def test_binary_garbage(self) -> None:
        """Binary garbage should be handled gracefully."""
        raw = b"\x00\xff\xfe\x80\x90\xa0"
        method, host, path, content_length = parse_http_request(raw)

        assert method == ""
        assert host == ""
        assert path == ""
        assert content_length == 0

    def test_partial_request(self) -> None:
        """Partial/truncated request should be handled gracefully."""
        raw = b"GET /bucket"
        method, host, path, content_length = parse_http_request(raw)

        assert method == "GET"
        assert path == "/bucket"

    def test_utf8_path(self) -> None:
        """UTF-8 encoded path should be handled."""
        raw = "GET /bucket/ключ HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n".encode("utf-8")
        method, host, path, content_length = parse_http_request(raw)

        assert method == "GET"
        assert "ключ" in path

    def test_multiple_colons_in_header_value(self) -> None:
        """Header values containing colons should be parsed correctly."""
        raw = b"GET / HTTP/1.1\r\nHost: [::1]:9000\r\n\r\n"
        method, host, path, content_length = parse_http_request(raw)

        assert host == "[::1]:9000"


class TestParseHttpResponse:
    """Tests for parse_http_response function."""

    def test_valid_200_response(self) -> None:
        """Parse a 200 OK response."""
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 200

    def test_valid_201_response(self) -> None:
        """Parse a 201 Created response."""
        raw = b"HTTP/1.1 201 Created\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 201

    def test_valid_204_response(self) -> None:
        """Parse a 204 No Content response (common for DELETE)."""
        raw = b"HTTP/1.1 204 No Content\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 204

    def test_valid_304_response(self) -> None:
        """Parse a 304 Not Modified response."""
        raw = b"HTTP/1.1 304 Not Modified\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 304

    def test_valid_400_response(self) -> None:
        """Parse a 400 Bad Request response."""
        raw = b"HTTP/1.1 400 Bad Request\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 400

    def test_valid_403_response(self) -> None:
        """Parse a 403 Forbidden response."""
        raw = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 403

    def test_valid_404_response(self) -> None:
        """Parse a 404 Not Found response."""
        raw = b"HTTP/1.1 404 Not Found\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 404

    def test_valid_500_response(self) -> None:
        """Parse a 500 Internal Server Error response."""
        raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 500

    def test_valid_503_response(self) -> None:
        """Parse a 503 Service Unavailable response."""
        raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 503

    def test_100_continue_response(self) -> None:
        """Parse a 100 Continue interim response."""
        raw = b"HTTP/1.1 100 Continue\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 100

    def test_http_10_response(self) -> None:
        """Parse an HTTP/1.0 response."""
        raw = b"HTTP/1.0 200 OK\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 200

    def test_empty_input(self) -> None:
        """Empty input should return 0."""
        status_code = parse_http_response(b"")

        assert status_code == 0

    def test_non_http_response(self) -> None:
        """Non-HTTP response should return 0."""
        raw = b"This is not an HTTP response"
        status_code = parse_http_response(raw)

        assert status_code == 0

    def test_malformed_status_code(self) -> None:
        """Malformed status code should return 0."""
        raw = b"HTTP/1.1 ABC OK\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 0

    def test_missing_status_code(self) -> None:
        """Missing status code should return 0."""
        raw = b"HTTP/1.1\r\n\r\n"
        status_code = parse_http_response(raw)

        assert status_code == 0

    def test_binary_garbage(self) -> None:
        """Binary garbage should return 0."""
        raw = b"\x00\xff\xfe\x80\x90\xa0"
        status_code = parse_http_response(raw)

        assert status_code == 0

    def test_partial_response(self) -> None:
        """Partial response parses whatever digits are available."""
        raw = b"HTTP/1.1 20"
        status_code = parse_http_response(raw)

        # The parser extracts "20" as the status code (doesn't validate 3 digits)
        assert status_code == 20

    def test_truncated_http_prefix(self) -> None:
        """Truncated HTTP prefix should return 0."""
        raw = b"HTTP"
        status_code = parse_http_response(raw)

        assert status_code == 0


class TestParseBucketEndpoint:
    """Tests for parse_bucket_endpoint function."""

    def test_path_style_simple(self) -> None:
        """Parse path-style URL: /bucket/key."""
        bucket, endpoint = parse_bucket_endpoint("s3.amazonaws.com", "/mybucket/mykey.txt")

        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_path_style_nested_key(self) -> None:
        """Parse path-style URL with nested key: /bucket/dir/subdir/key."""
        bucket, endpoint = parse_bucket_endpoint("s3.amazonaws.com", "/bucket/dir/subdir/key.txt")

        assert bucket == "bucket"
        assert endpoint == "s3.amazonaws.com"

    def test_path_style_bucket_only(self) -> None:
        """Parse path-style URL with bucket only: /bucket."""
        bucket, endpoint = parse_bucket_endpoint("s3.amazonaws.com", "/mybucket")

        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_path_style_with_query_string(self) -> None:
        """Parse path-style URL with query string."""
        bucket, endpoint = parse_bucket_endpoint(
            "s3.amazonaws.com", "/mybucket/mykey?uploadId=abc123"
        )

        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_virtual_host_style_s3(self) -> None:
        """Parse virtual-host-style URL for AWS S3 (path-style fallback).

        Note: The implementation prioritizes path-style extraction. For paths
        like "/mykey.txt", the first path component is treated as the bucket.
        Virtual-host-style is only used when path doesn't contain a bucket.
        """
        # When path starts with "/key" (no bucket in path), path-style extracts key as bucket
        bucket, endpoint = parse_bucket_endpoint("mybucket.s3.amazonaws.com", "/mykey.txt")
        assert bucket == "mykey.txt"  # Path-style takes precedence
        assert endpoint == "mybucket.s3.amazonaws.com"

        # For root path, virtual-host-style is used
        bucket, endpoint = parse_bucket_endpoint("mybucket.s3.amazonaws.com", "/")
        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_virtual_host_style_regional(self) -> None:
        """Parse virtual-host-style URL with regional endpoint.

        Virtual-host-style is used when path is root or empty.
        """
        # Root path triggers virtual-host-style extraction
        bucket, endpoint = parse_bucket_endpoint(
            "mybucket.s3.us-west-2.amazonaws.com", "/"
        )

        assert bucket == "mybucket"
        assert endpoint == "s3.us-west-2.amazonaws.com"

    def test_virtual_host_style_minio(self) -> None:
        """Parse virtual-host-style URL for MinIO.

        Virtual-host-style is used when path is root or empty.
        """
        # Root path triggers virtual-host-style extraction
        bucket, endpoint = parse_bucket_endpoint("mybucket.minio.local", "/")

        assert bucket == "mybucket"
        assert endpoint == "minio.local"

    def test_path_style_with_virtual_host_domain(self) -> None:
        """Path-style takes precedence even with virtual-host-style domain."""
        bucket, endpoint = parse_bucket_endpoint(
            "anotherbucket.s3.amazonaws.com", "/mybucket/mykey.txt"
        )

        # Path-style bucket extraction wins
        assert bucket == "mybucket"
        assert endpoint == "anotherbucket.s3.amazonaws.com"

    def test_path_style_takes_precedence(self) -> None:
        """Path-style should take precedence when bucket is in path."""
        bucket, endpoint = parse_bucket_endpoint(
            "mybucket.s3.amazonaws.com", "/otherbucket/key"
        )

        # Path-style bucket should be extracted
        assert bucket == "otherbucket"
        assert endpoint == "mybucket.s3.amazonaws.com"

    def test_empty_host_and_path(self) -> None:
        """Empty host and path should return empty strings."""
        bucket, endpoint = parse_bucket_endpoint("", "")

        assert bucket == ""
        assert endpoint == ""

    def test_root_path(self) -> None:
        """Root path (/) should return empty bucket from path."""
        bucket, endpoint = parse_bucket_endpoint("mybucket.s3.amazonaws.com", "/")

        # Virtual-host style should be used
        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_simple_host_no_subdomain(self) -> None:
        """Host without subdomain should use path-style only."""
        bucket, endpoint = parse_bucket_endpoint("localhost", "/mybucket/key")

        assert bucket == "mybucket"
        assert endpoint == "localhost"

    def test_host_with_port(self) -> None:
        """Host with port should be preserved."""
        bucket, endpoint = parse_bucket_endpoint("localhost:9000", "/mybucket/key")

        assert bucket == "mybucket"
        assert endpoint == "localhost:9000"

    def test_unicode_bucket_name(self) -> None:
        """Unicode characters in bucket name should be preserved."""
        bucket, endpoint = parse_bucket_endpoint("s3.amazonaws.com", "/тест/key")

        assert bucket == "тест"
        assert endpoint == "s3.amazonaws.com"

    def test_url_encoded_path(self) -> None:
        """URL-encoded path components should be handled."""
        bucket, endpoint = parse_bucket_endpoint(
            "s3.amazonaws.com", "/mybucket/my%20key%2Fwith%20spaces"
        )

        assert bucket == "mybucket"

    def test_list_operation_path(self) -> None:
        """List operation with prefix query should extract bucket."""
        bucket, endpoint = parse_bucket_endpoint(
            "s3.amazonaws.com", "/mybucket?list-type=2&prefix=myprefix/"
        )

        assert bucket == "mybucket"
        assert endpoint == "s3.amazonaws.com"

    def test_multipart_upload_path(self) -> None:
        """Multipart upload path should extract bucket correctly."""
        bucket, endpoint = parse_bucket_endpoint(
            "s3.amazonaws.com", "/mybucket/mykey?uploads"
        )

        assert bucket == "mybucket"

    def test_ipv4_host(self) -> None:
        """IPv4 address as host should be handled."""
        bucket, endpoint = parse_bucket_endpoint("192.168.1.100", "/mybucket/key")

        assert bucket == "mybucket"
        assert endpoint == "192.168.1.100"

    def test_ipv6_host(self) -> None:
        """IPv6 address as host should be handled."""
        bucket, endpoint = parse_bucket_endpoint("[::1]", "/mybucket/key")

        assert bucket == "mybucket"
        assert endpoint == "[::1]"
