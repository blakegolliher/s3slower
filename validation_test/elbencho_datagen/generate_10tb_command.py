#!/usr/bin/env python3

"""
Python script to generate elbencho commands for creating 10TB of data
across 1000 directories nested 3 levels deep with 1MB files.

This approach generates multiple elbencho commands that can be run
in parallel or sequentially to achieve the desired structure.
"""

import os
import math

# Configuration
TOTAL_SIZE_TB = 10
FILE_SIZE_MB = 1
TOTAL_DIRS = 1000
NESTING_DEPTH = 3

# Calculations
TOTAL_SIZE_BYTES = TOTAL_SIZE_TB * 1024**4
FILE_SIZE_BYTES = FILE_SIZE_MB * 1024**2
TOTAL_FILES = TOTAL_SIZE_BYTES // FILE_SIZE_BYTES
FILES_PER_DIR = math.ceil(TOTAL_FILES / TOTAL_DIRS)

# Directory structure: 10 x 10 x 10 = 1000 leaf directories
DIRS_PER_LEVEL = 10

print(f"""
Configuration Summary:
- Total data size: {TOTAL_SIZE_TB}TB
- File size: {FILE_SIZE_MB}MB
- Total files needed: {TOTAL_FILES:,}
- Total directories: {TOTAL_DIRS}
- Files per directory: {FILES_PER_DIR:,}
- Directory structure: {DIRS_PER_LEVEL} x {DIRS_PER_LEVEL} x {DIRS_PER_LEVEL} (3 levels deep)
""")

print("\nGenerating elbencho commands...\n")

# Generate commands file
with open("elbencho_10tb_commands.sh", "w") as f:
    f.write("#!/bin/bash\n\n")
    f.write("# Elbencho commands to create 10TB of data\n")
    f.write("# Can be run sequentially or modified for parallel execution\n\n")
    f.write("TARGET_DIR=\"/path/to/your/storage\"  # Change this!\n")
    f.write("THREADS=16  # Adjust based on your system\n\n")
    
    # Create base directories first
    f.write("# Create base directory structure\n")
    for i in range(DIRS_PER_LEVEL):
        for j in range(DIRS_PER_LEVEL):
            for k in range(DIRS_PER_LEVEL):
                dir_path = f"dir{i}/dir{j}/dir{k}"
                f.write(f"mkdir -p \"$TARGET_DIR/{dir_path}\"\n")
    
    f.write("\n# Write files to each directory\n")
    f.write("# Note: These commands can be run in parallel for faster execution\n\n")
    
    cmd_count = 0
    for i in range(DIRS_PER_LEVEL):
        for j in range(DIRS_PER_LEVEL):
            for k in range(DIRS_PER_LEVEL):
                dir_path = f"dir{i}/dir{j}/dir{k}"
                cmd_count += 1
                
                # Generate elbencho command for this directory
                f.write(f"# Command {cmd_count}/{TOTAL_DIRS}\n")
                f.write(f"elbencho \\\n")
                f.write(f"    --write \\\n")
                f.write(f"    --threads $THREADS \\\n")
                f.write(f"    --dirs 0 \\\n")  # No subdirs, write directly to target
                f.write(f"    --files {FILES_PER_DIR} \\\n")
                f.write(f"    --size 1M \\\n")
                f.write(f"    --block 1M \\\n")
                f.write(f"    --direct \\\n")
                f.write(f"    \"$TARGET_DIR/{dir_path}\"\n\n")

print("Generated elbencho_10tb_commands.sh")
print("\nTo use:")
print("1. Edit the TARGET_DIR in the generated script")
print("2. Make it executable: chmod +x elbencho_10tb_commands.sh")
print("3. Run it: ./elbencho_10tb_commands.sh")
print("\nFor faster execution, you can run multiple elbencho commands in parallel.")
