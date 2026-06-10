# Creating 10TB of Data with Elbencho

This directory contains scripts to create 10TB of data spread across 1000 directories nested 3 levels deep with 1MB files using elbencho.

## Requirements Summary

- **Total data**: 10TB (10,995,116,277,760 bytes)
- **File size**: 1MB each
- **Total files**: 10,485,760 files
- **Directory structure**: 1000 directories nested 3 levels deep
- **Files per directory**: 10,486 files

## Available Approaches

### Approach 1: Full Treefile Generation (Recommended for exact requirements)

This approach creates the exact nested directory structure (3 levels deep) as requested.

```bash
# Step 1: Generate the treefile (this will take a few minutes)
chmod +x generate_10tb_treefile.sh
./generate_10tb_treefile.sh

# Step 2: Run elbencho with the treefile
chmod +x run_elbencho_10tb.sh
# Edit run_elbencho_10tb.sh to set your TARGET_DIR
./run_elbencho_10tb.sh
```

**Pros**: 
- Exact directory structure as requested (3 levels deep)
- Single elbencho command to create everything

**Cons**: 
- Treefile generation takes time and creates a large file (~1GB)
- Requires sufficient disk space for the treefile

### Approach 2: Simplified Single-Level Approach

If the exact 3-level nesting isn't critical, this creates 1000 directories at a single level:

```bash
chmod +x elbencho_10tb_simple.sh
# Edit the script to set your TARGET_DIR
./elbencho_10tb_simple.sh
```

**Pros**: 
- No treefile needed
- Single simple command
- Fastest approach

**Cons**: 
- Creates flat directory structure (not nested)

### Approach 3: Python-Generated Commands

This generates shell commands to create the exact structure without a large treefile:

```bash
# Generate the commands
python3 generate_10tb_command.py

# Run the generated commands
chmod +x elbencho_10tb_commands.sh
# Edit elbencho_10tb_commands.sh to set your TARGET_DIR
./elbencho_10tb_commands.sh
```

**Pros**: 
- No large treefile needed
- Can be parallelized for faster execution
- Exact directory structure

**Cons**: 
- Runs multiple elbencho commands (1000 total)

## Performance Tips

1. **Use multiple threads**: Adjust the `THREADS` variable based on your CPU cores
2. **Use direct I/O**: All scripts use `--direct` flag to bypass OS cache
3. **Storage considerations**: Ensure you have at least 11TB of free space
4. **Parallel execution**: For Approach 3, you can modify the script to run multiple elbencho commands in parallel

## Example Parallel Execution (Approach 3)

To run commands in parallel batches:

```bash
# Run 10 elbencho processes in parallel
cat elbencho_10tb_commands.sh | grep "^elbencho" | xargs -P 10 -I {} bash -c '{}'
```

## Verification

After creation, verify the data:

```bash
# Check total size
du -sh /path/to/your/storage

# Count files
find /path/to/your/storage -type f | wc -l

# Count directories
find /path/to/your/storage -type d | wc -l
```

## Cleanup

To remove all created data:

```bash
# Use elbencho to delete (if you have the treefile)
elbencho --treefile 10tb_nested_dirs.treefile --delfiles --deldirs /path/to/your/storage

# Or use rm (be careful!)
rm -rf /path/to/your/storage/*
```

## Notes

- Total creation time depends on your storage performance
- With fast NVMe storage and multiple threads, expect 1-3 hours
- Monitor disk I/O during creation with tools like `iostat` or `iotop`
- The actual disk usage might be slightly more than 10TB due to filesystem overhead

