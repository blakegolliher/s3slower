#!/bin/bash

# Script to quickly remove all files from the nested directory structure
# Uses perl for fast file deletion

TARGET_DIR="/path/to/your/storage"  # CHANGE THIS to your actual directory!

echo "Starting cleanup of elbencho files..."
echo "Target directory: $TARGET_DIR"

# Navigate to the target directory
cd "$TARGET_DIR" || { echo "Failed to cd to $TARGET_DIR"; exit 1; }

# Counter for progress
count=0

# Loop through the 3-level nested structure
for i in {0..9}; do
    for j in {0..9}; do
        for k in {0..9}; do
            dir_path="dir${i}/dir${j}/dir${k}"
            
            if [ -d "$dir_path" ]; then
                echo -n "Cleaning $dir_path... "
                cd "$dir_path" || continue
                
                # Use perl to quickly delete all files
                perl -e 'for(<*>){unlink}'
                
                # Go back to base directory
                cd "$TARGET_DIR"
                
                ((count++))
                echo "done ($count/1000)"
            fi
        done
    done
done

echo ""
echo "File cleanup complete!"
echo "Cleaned $count directories"

# Optional: Remove empty directories too
echo ""
read -p "Do you want to remove the empty directories too? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing empty directories..."
    find "$TARGET_DIR" -type d -empty -delete
    echo "Directories removed!"
fi

