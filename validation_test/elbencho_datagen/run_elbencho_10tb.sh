#!/bin/bash

# Script to run elbencho to create 10TB of data using the generated treefile

# Configuration
TREEFILE="10tb_nested_dirs.treefile"
TARGET_DIR="/path/to/your/storage"  # Change this to your target directory
THREADS=16  # Adjust based on your system's capabilities
BLOCK_SIZE="1M"  # Block size for I/O operations

# Check if treefile exists
if [ ! -f "$TREEFILE" ]; then
    echo "Error: Treefile '$TREEFILE' not found!"
    echo "Please run generate_10tb_treefile.sh first to create the treefile."
    exit 1
fi

echo "Starting elbencho to create 10TB of data..."
echo "Target directory: $TARGET_DIR"
echo "Using $THREADS threads"
echo ""

# Create directories and write files
echo "Phase 1: Creating directories and writing files..."
elbencho \
    --treefile "$TREEFILE" \
    --write \
    --mkdirs \
    --threads $THREADS \
    --block $BLOCK_SIZE \
    --direct \
    "$TARGET_DIR"

# Optional: Verify the data was written correctly
# echo ""
# echo "Phase 2: Reading files to verify..."
# elbencho \
#     --treefile "$TREEFILE" \
#     --read \
#     --threads $THREADS \
#     --block $BLOCK_SIZE \
#     --direct \
#     "$TARGET_DIR"

echo ""
echo "Data creation complete!"

# Show statistics
echo ""
echo "Storage usage:"
du -sh "$TARGET_DIR"
