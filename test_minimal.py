#!/usr/bin/env python3
"""
Minimal test to isolate the sh syntax error
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

print("Starting minimal test...")

# Test 1: Import logger
print("\n1. Testing logger import...")
try:
    from s3slower.logger import get_logger, COLORS
    logger = get_logger("test", COLORS.cyan)
    logger.info("Logger working correctly")
    print("   ✓ Logger import OK")
except Exception as e:
    print(f"   ✗ Logger import failed: {e}")

# Test 2: Import s3ops
print("\n2. Testing s3ops import...")
try:
    from s3slower import s3ops
    print("   ✓ s3ops import OK")
except Exception as e:
    print(f"   ✗ s3ops import failed: {e}")

# Test 3: Import s3ops_enhanced
print("\n3. Testing s3ops_enhanced import...")
try:
    from s3slower import s3ops_enhanced
    print("   ✓ s3ops_enhanced import OK")
except Exception as e:
    print(f"   ✗ s3ops_enhanced import failed: {e}")

# Test 4: Create monitor without starting it
print("\n4. Testing monitor creation (no BPF load)...")
try:
    from s3slower.s3ops import S3LatencyMonitor
    # Don't start it, just create it
    monitor = S3LatencyMonitor()
    print("   ✓ Monitor created successfully")
except Exception as e:
    print(f"   ✗ Monitor creation failed: {e}")
    import traceback
    traceback.print_exc()

print("\nMinimal test complete.")
