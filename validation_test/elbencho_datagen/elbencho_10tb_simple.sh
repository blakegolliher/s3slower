#!/bin/bash

# Alternative simpler approach using elbencho without treefile
# This creates 10TB of data across 1000 directories (but only 1 level deep)

TARGET_DIR="/path/to/your/storage"  # Change this to your target directory
THREADS=16  # Adjust based on your system
FILES_PER_DIR=10486  # Files per directory to reach ~10TB total
FILE_SIZE="1M"  # 1MB files
BLOCK_SIZE="1M"

echo "Creating 10TB of data using elbencho (simplified approach)..."
echo "Note: This creates 1000 directories at one level, not nested 3 deep"
echo ""

# Using elbencho with 1000 directories and appropriate number of files
elbencho \
    --write \
    --mkdirs \
    --threads $THREADS \
    --dirs 1000 \
    --files $FILES_PER_DIR \
    --size $FILE_SIZE \
    --block $BLOCK_SIZE \
    --direct \
    "$TARGET_DIR"

echo ""
echo "Data creation complete!"
echo "Created: 1000 directories × $FILES_PER_DIR files × 1MB = ~10TB"

# Show actual usage
echo ""
echo "Actual storage usage:"
du -sh "$TARGET_DIR"

