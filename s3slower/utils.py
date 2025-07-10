# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import os
import signal
import asyncio
import argparse
from typing import List, Dict, Any, Union


class InvalidArgument(Exception):
    """Exception raised for invalid arguments"""
    pass


def set_signal_handler(handler_func, loop):
    """Set up signal handlers for graceful shutdown"""
    for sig in [signal.SIGTERM, signal.SIGINT]:
        try:
            loop.add_signal_handler(sig, handler_func, sig, None)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, handler_func)


async def await_until_event_or_timeout(timeout: int, stop_event: asyncio.Event):
    """Wait for either timeout or stop event"""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=timeout)
        return True  # Event was set
    except asyncio.TimeoutError:
        return False  # Timeout occurred


def maybe_list_parse(value: str) -> List[str]:
    """Parse comma-separated string into list"""
    if value is None:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def maybe_bool_parse(value: Union[str, bool]) -> bool:
    """Parse string or bool value to bool"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', 'yes', '1', 'on')
    return bool(value)


def parse_args_options_from_namespace(namespace: Dict[str, Any], parser: argparse.ArgumentParser) -> argparse.Namespace:
    """Parse arguments from a namespace dictionary"""
    args = []
    for key, value in namespace.items():
        if value is not None:
            if isinstance(value, bool):
                if value:
                    args.append(f"--{key.replace('_', '-')}")
            elif isinstance(value, list):
                for item in value:
                    args.extend([f"--{key.replace('_', '-')}", str(item)])
            else:
                args.extend([f"--{key.replace('_', '-')}", str(value)])
    
    return parser.parse_args(args)


def flatten_keys(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> List[str]:
    """Flatten nested dictionary keys"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_keys(v, new_key, sep=sep))
        else:
            items.append(new_key)
    return items


def extract_s3_operation(method: str, url: str) -> str:
    """
    Extract S3 operation from HTTP method and URL.
    
    This function identifies specific S3 operations based on the HTTP method
    and query parameters in the URL.
    
    Args:
        method: HTTP method (GET, PUT, POST, DELETE, HEAD)
        url: Request URL with potential query parameters
        
    Returns:
        String identifying the S3 operation or empty string if unknown
        
    Examples:
        >>> extract_s3_operation("PUT", "/bucket/key?uploadId=123&partNumber=1")
        "UploadPart(1)"
        >>> extract_s3_operation("GET", "/bucket/key")
        "GetObject"
    """
    if '?' not in url:
        # Simple operations without query parameters
        operation_map = {
            "PUT": "PutObject",
            "GET": "GetObject", 
            "HEAD": "HeadObject",
            "DELETE": "DeleteObject",
            "POST": "PostObject"
        }
        return operation_map.get(method, "")

    # Parse query parameters for complex operations
    try:
        base_url, query_string = url.split('?', 1)
        params = {}
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
            else:
                params[param] = ""

        # Detect S3 multipart and other operations
        if method == "POST":
            if "uploads" in params:
                return "InitMultipart"
            elif "uploadId" in params and "partNumber" not in params:
                return "CompleteMultipart"
            elif "delete" in params:
                return "DeleteMultiple"
            else:
                return "PostObject"
        elif method == "PUT":
            if "uploadId" in params and "partNumber" in params:
                part_num = params.get("partNumber", "?")
                return f"UploadPart({part_num})"
            else:
                return "PutObject"
        elif method == "GET":
            if "uploadId" in params:
                return "ListParts"
            elif "uploads" in params:
                return "ListMultiparts"
            else:
                return "GetObject"
        elif method == "DELETE":
            if "uploadId" in params:
                return "AbortMultipart"
            else:
                return "DeleteObject"
        elif method == "HEAD":
            return "HeadObject"

    except Exception:
        pass

    return ""


def extract_method_url(data: bytes) -> tuple:
    """
    Extract HTTP method and URL from request data.
    
    Args:
        data: Raw HTTP request data
        
    Returns:
        Tuple of (method, url, s3_operation)
    """
    try:
        data_str = data.decode('utf-8', errors='ignore')
        if not data_str:
            return "?", "?", "?"

        lines = data_str.split('\r\n')
        if not lines:
            return "?", "?", "?"

        first_line = lines[0]
        parts = first_line.split(' ')
        if len(parts) >= 3:
            method = parts[0]
            url = parts[1]
            
            # Detect S3 operation
            s3_op = extract_s3_operation(method, url)
            
            return method, url, s3_op
        return "?", "?", "?"
    except Exception:
        return "?", "?", "?" 