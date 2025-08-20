#!/usr/bin/env python3
"""
Direct test of the enhanced S3 slower using the kernel-compatible version
"""

import sys
import time
import logging
from bcc import BPF
import os

# Setup logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('s3slower_enhanced')

def main():
    print("Enhanced S3 Latency Monitor (Kernel Compatible)")
    print("=" * 50)
    
    # Load the enhanced BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_enhanced_kernel_compat.c")
    
    try:
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling enhanced BPF program...")
        b = BPF(text=bpf_text)
        logger.info("✓ BPF program compiled successfully!")
        
        # Quick test - just verify it loads
        print("\nEnhanced BPF program loaded successfully!")
        print("Features:")
        print("- 256-byte buffer (vs 64 in original)")
        print("- Enhanced HTTP method detection (GET, PUT, POST, HEAD, DELETE, PATCH, OPTIONS)")
        print("- S3-specific pattern detection (x-amz-*, Host headers, 'bucket' in paths)")
        print("- Better multipart request handling")
        print("- Additional syscall coverage (send, recv, sendto, recvfrom, sendmsg, recvmsg)")
        
    except Exception as e:
        logger.error(f"Failed to load enhanced BPF program: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
