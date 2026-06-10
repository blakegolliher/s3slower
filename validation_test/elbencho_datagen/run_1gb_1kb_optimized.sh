#!/bin/bash

# Optimized script for 1GB of 1KB files with high thread count and I/O depth

# Configuration
TARGET_DIR="/path/to/your/storage"  # CHANGE THIS!
TREEFILE="1gb_1kb.treefile"
FILE_SIZE=1024  # 1KB in bytes
FILES_PER_DIR=1049  # ~1GB total across 1000 dirs
THREADS=90
IODEPTH=32

echo "Creating treefile for 1GB of 1KB files..."

# Clear/create the treefile
> "$TREEFILE"

# Create the nested directory structure (10 x 10 x 10 = 1000 directories)
for i in {0..9}; do
    for j in {0..9}; do
        for k in {0..9}; do
            echo "d dir${i}/dir${j}/dir${k}" >> "$TREEFILE"
        done
    done
done

# Add files to each leaf directory
for i in {0..9}; do
    for j in {0..9}; do
        for k in {0..9}; do
            for f in $(seq 1 $FILES_PER_DIR); do
                echo "f $FILE_SIZE dir${i}/dir${j}/dir${k}/file_${f}.dat" >> "$TREEFILE"
            done
        done
    done
done

echo "Treefile created!"
echo ""
echo "Starting elbencho with optimized settings:"
echo "- 90 threads (for 96 core system)"
echo "- I/O depth: 32"
echo "- Block size: 1K"
echo "- Direct I/O: DISABLED"
echo "- Target: $TARGET_DIR"
echo ""

# Run elbencho with optimized settings
elbencho \
    --treefile "$TREEFILE" \
    --write \
    --mkdirs \
    --threads $THREADS \
    --block 1K \
    --iodepth $IODEPTH \
    "$TARGET_DIR"

echo ""
echo "Complete! Check the results above."
