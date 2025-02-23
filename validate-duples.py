#!/usr/bin/python

import os
import hashlib
import subprocess
import time
import datetime
from collections import defaultdict
from PIL import Image

# Use fdupes to create the file_list.txt
# Run: time sudo fdupes -r /path/to/find/dupes > file_list.txt
# This script checks JPG and video files from file_list.txt and creates file_list-fixed.txt with good files. After that, use backup-dupes.py

# Global variable to track the total size of broken files
total_broken_size = 0

# Generate log file name with current date and time
log_filename = f"file_check_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log_message(message):
    """Write log messages to both console and file."""
    print(message)
    with open(log_filename, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def compute_sha512(file_path):
    sha512 = hashlib.sha512()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha512.update(chunk)
        return sha512.hexdigest()
    except Exception as e:
        log_message(f"DEBUG: Error computing SHA512 for {file_path}: {e}")
        return None

def get_human_readable_size(file_path):
    """Returns the human-readable size of a file (e.g., KB, MB, GB)."""
    size_in_bytes = os.path.getsize(file_path)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0

def check_image(file_path):
    """Check if an image is valid by opening it."""
    try:
        with Image.open(file_path) as img:
            img.verify()
        return "OK"
    except Exception as e:
        return f"Image Error: {e}"

def check_video(file_path):
    """Compare video integrity check times using CPU vs. QSV (hardware acceleration)."""
    log_message(f"Checking: {file_path}")

    start_qsv = time.time()
    cmd_qsv = [
        "ffmpeg",
        "-init_hw_device", "qsv=hw",
        "-filter_hw_device", "hw",
        "-hwaccel", "qsv",
        "-v", "error",
        "-i", file_path,
        "-f", "null", "-"
    ]
    result_qsv = subprocess.run(cmd_qsv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    qsv_time = time.time() - start_qsv
    qsv_status = "OK" if result_qsv.returncode == 0 else f"Error: {result_qsv.stderr.strip()}"

    log_message(f"  QSV Check: {qsv_time:.2f}s - {qsv_status}")

    return {
        "qsv_time": qsv_time,
        "qsv_status": qsv_status
    }

def check_file(file_path):
    """Function to check file integrity"""
    global total_broken_size

    ext = os.path.splitext(file_path)[1].lower()
    log_message(f"DEBUG: Checking file type {file_path}")

    if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]:
        result = check_image(file_path)
    elif ext in [".mp4", ".mov", ".avi", ".mkv", ".flv", ".ts"]:
        result = check_video(file_path)
    else:
        return "Unknown type - skipped"
    
    # If the file is broken, add its size to the total.
    # For images, the result is a string; for videos, it's a dict.
    if (isinstance(result, str) and "Error" in result) or \
       (isinstance(result, dict) and result.get("qsv_status", "").startswith("Error")):
        file_size = os.path.getsize(file_path)
        total_broken_size += file_size
        log_message(f"Broken file detected: {file_path} (Size: {file_size / (1024 * 1024):.2f} MB)")

    return result

def is_integrity_ok(result):
    """Helper function to determine if the integrity check passed."""
    if isinstance(result, str):
        return result == "OK"
    elif isinstance(result, dict):
        return result.get("qsv_status") == "OK"
    return False

def print_broken_file_summary():
    """Print the total size of all broken files found."""
    global total_broken_size
    log_message(f"Total size of broken files: {total_broken_size / (1024 * 1024):.2f} MB")

def main():
    # Read the source file with blocks separated by double newlines.
    with open("file_list.txt", "r", encoding="utf-8") as f:
        content = f.read()
    
    blocks = [block.strip() for block in content.strip().split("\n\n") if block.strip()]
    totalblocks = len(blocks)
    log_message(f"DEBUG: Total blocks found: {totalblocks}")
    
    # Group records by a combination of block index and file hash.
    file_groups = {}
    checked_files = []
    total_broken_files = 0
    failed_blocks = set()
    
    # Process each block with debug output.
    for block_index, block in enumerate(blocks):
        log_message(f"DEBUG: Processing block {block_index + 1} of {totalblocks}")
        
        # Each block may have multiple file paths (one per line)
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        block_hashes = {}
        
        # Compute the hashes for all files in the block.
        for file_path in lines:
            log_message(f"DEBUG: Checking file: {file_path}")
            file_hash = compute_sha512(file_path)
            if file_hash:
                block_hashes.setdefault(file_hash, []).append(file_path)
        
        # For each unique hash in the block, check integrity using one selected file,
        # but store all file paths sharing that hash.
        for file_hash, file_paths in block_hashes.items():
            if len(file_paths) > 1:
                log_message(f"\nFile(s) with hash {file_hash} found in multiple locations:")
                for file_path in file_paths:
                    log_message(f"  {file_path}")
            
            selected_file = file_paths[0]
            file_size = get_human_readable_size(selected_file)
            log_message(f"  Selected file for integrity check: {selected_file} (Size: {file_size})")
            check_result = check_file(selected_file)
            log_message(f"DEBUG: Integrity check for {selected_file}: {check_result}")
            
            if not is_integrity_ok(check_result):
                total_broken_files += 1
                failed_blocks.add(block_index)
            
            # Store group using key (block_index, file_hash)
            file_groups[(block_index, file_hash)] = {
                "block": block_index,
                "files": file_paths,
                "hash": file_hash,
                "check": check_result,
                "size": file_size
            }
            
            # If the file passed the check, add all its associated file paths to checked_files.
            if is_integrity_ok(check_result):
                checked_files.extend(file_paths)
    
    # Write the new fixed text file with files that passed the integrity check.
    fixed_txt_filename = "file_list-fixed.txt"
    with open(fixed_txt_filename, "w", encoding="utf-8") as f:
        for block_index in range(totalblocks):
            block_files = []
            for (b, h), group in file_groups.items():
                if b == block_index and is_integrity_ok(group["check"]):
                    block_files.extend(group["files"])
            if block_files:
                f.write("\n".join(block_files) + "\n\n")
    
    log_message(f"Fixed file list created: {fixed_txt_filename}")

    # Output statistics
    log_message(f"\nTotal blocks checked: {totalblocks}")
    log_message(f"Total broken files: {total_broken_files}")
    log_message(f"Failed blocks: {len(failed_blocks)} out of {totalblocks} blocks.")
    print_broken_file_summary()

if __name__ == "__main__":
    main()
