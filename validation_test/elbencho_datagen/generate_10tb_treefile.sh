#!/bin/bash

# Script to generate a treefile for elbencho to create 10TB of data
# across 1000 directories nested 3 levels deep with 1MB files

TREEFILE="10tb_nested_dirs.treefile"
FILE_SIZE=1048576  # 1MB in bytes
FILES_PER_DIR=10486  # To get approximately 10TB total

echo "Generating treefile for 10TB data across 1000 directories..."

# Clear/create the treefile
> "$TREEFILE"

# Create the nested directory structure
# 10 x 10 x 10 = 1000 directories at the leaf level
for i in {0..9}; do
    for j in {0..9}; do
        for k in {0..9}; do
            # Create directory entry in treefile
            echo "d dir${i}/dir${j}/dir${k}" >> "$TREEFILE"
        done
    done
done

echo "Added 1000 directories to treefile"

# Add files to each leaf directory
file_count=0
for i in {0..9}; do
    for j in {0..9}; do
        for k in {0..9}; do
            # Add files for this directory
            for f in $(seq 1 $FILES_PER_DIR); do
                echo "f $FILE_SIZE dir${i}/dir${j}/dir${k}/file_${f}.dat" >> "$TREEFILE"
                ((file_count++))
                
                # Show progress every 100,000 files
                if [ $((file_count % 100000)) -eq 0 ]; then
                    echo "Progress: $file_count files added..."
                fi
            done
        done
    done
done

echo "Treefile generation complete!"
echo "Total directories: 1000"
echo "Total files: $file_count"
echo "Total data size: $(echo "scale=2; $file_count * $FILE_SIZE / 1024 / 1024 / 1024 / 1024" | bc) TB"
echo "Treefile saved as: $TREEFILE"
