#!/usr/bin/python

import argparse
import hashlib
import shutil
import sys
import re
import os
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from PIL import Image

# Use fdupes for create the file file_list.txt
# time sudo fdupes -r /path/to/find/dupes >file_list.txt

# Global counters for statistics
total_duplicate_space = 0
total_backup_space = 0
deleted_files_count = 0

SOURCE_FILE = "file_list.txt"  # Change to your actual text file
DEST_BASE_DIR = Path("/backup")
#/mnt-fs/backup")  # Base backup folder
LOG_FILE = "backup.log"  # Log file to store all console outputs

DATE_PATTERN = re.compile(r"PXL_(\d{8})")  # Extracts YYYYMMDD from filenames
TRASHED_PATTERN = re.compile(r"\.trashed-\d+-")  # Matches `.trashed-*` prefix

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
def log_message(message):
    """Log to both console and file."""
    print(message)
    logging.info(message)

def get_human_size(bytes_size):
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"

def set_folder_timestamp(folder, target_date):
    """Set folder modification and access time based on a given timestamp."""
    try:
        folder = Path(folder)
        if folder.exists():
            ts = target_date.timestamp()
            os.utime(folder, (ts, ts))
            log_message(f"Updated timestamp for {folder} to {target_date.strftime('%Y-%m-%d')}")
    except Exception as e:
        log_message(f"Error updating timestamp for {folder}: {e}")

def clean_filename(filename):
    """Remove .trashed-* prefix from filename."""
    return TRASHED_PATTERN.sub("", filename)

def calculate_sha512(file_path):
    """Calculate SHA-512 checksum of a file."""
    try:
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha512.update(chunk)
        return sha512.hexdigest()
    except Exception as e:
        log_message(f"Error calculating hash for {file_path}: {e}")
        sys.exit(1)

def has_exif(file_path):
    """Check if a JPG file contains EXIF metadata."""
    try:
        with Image.open(file_path) as img:
            return bool(img.getexif())
    except Exception:
        return False

def extract_date_from_filename(filename):
    """Extract date from filename in YYYYMMDD format."""
    match = DATE_PATTERN.search(filename)
    if match:
        return datetime.strptime(match.group(1), "%Y%m%d")
    return None

def extract_mp4_creation_time(file_path):
    """Extract creation time from MP4 metadata using ffprobe."""
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format_tags=creation_time",
             "-of", "default=noprint_wrappers=1:nokey=1", str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        creation_time = result.stdout.strip()
        if creation_time:
            return datetime.strptime(creation_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception as e:
        log_message(f"Error extracting creation time from {file_path}: {e}")
    return None

def process_file_blocks(file_path, delete_sources=False):
    """Process the file list, group files by empty lines, and validate checksums."""
    with open(file_path, "r") as f:
        lines = [line.strip() for line in f.readlines()]

    blocks = []
    current_block = []
    for line in lines:
        if not line:  # Empty line found
            if current_block:
                blocks.append(current_block)
                current_block = []
        else:
            current_block.append(line)
    if current_block:
        blocks.append(current_block)

    for block in blocks:
        validate_and_backup(block, delete_sources)

    # After processing all blocks, print summary statistics.
    log_message("\n==== Backup Statistics ====")
    log_message(f"Total space occupied by duplicate files: {get_human_size(total_duplicate_space)}")
    log_message(f"Total space occupied by backed-up files: {get_human_size(total_backup_space)}")
    if delete_sources:
        log_message(f"Total number of source files deleted: {deleted_files_count}")
    log_message("Backup process completed successfully.")

def validate_and_backup(file_group, delete_sources):
    """Validate SHA-512 checksums for a group of files and perform backup."""
    global total_duplicate_space, total_backup_space, deleted_files_count

    if not file_group:
        return

    checksums = {}
    for file in file_group:
        file_path = Path(file)
        if not file_path.exists():
            log_message(f"Error: File not found - {file}")
            sys.exit(1)
        if file_path.suffix.lower() not in {".jpg", ".jpeg", ".mov", ".mp4"}:
            log_message(f"Skipping unsupported file: {file}")
            continue
        if file_path.suffix.lower() in {".jpg", ".jpeg"} and not has_exif(file_path):
            log_message(f"Skipping JPG without EXIF: {file}")
            continue
        file_hash = calculate_sha512(file_path)
        checksums[file] = file_hash

    if not checksums:
        log_message("No valid files to process in this block.")
        return

    unique_hashes = set(checksums.values())
    if len(unique_hashes) > 1:
        log_message("Error: Files in the same group have different checksums!")
        sys.exit(1)

    # Update duplicate space statistics.
    duplicate_size = sum(Path(f).stat().st_size for f in checksums if Path(f).exists())
    total_duplicate_space += duplicate_size

    first_valid_file = list(checksums.keys())[0]
    cleaned_name = clean_filename(Path(first_valid_file).name)
    file_date = extract_date_from_filename(cleaned_name)

    # Handle MP4 files without a date in the name
    if not file_date and first_valid_file.lower().endswith(".mp4"):
        file_date = extract_mp4_creation_time(first_valid_file)
        if file_date:
            log_message(f"Restored date from metadata for {cleaned_name}: {file_date.strftime('%Y/%m/%d')}")

    # If no valid date is found, backup to 'UNKNOWN' folder.
    if not file_date:
        log_message(f"Error: Could not extract date for {cleaned_name}. Backing up to 'UNKNOWN' folder.")
        year_folder = DEST_BASE_DIR / "UNKNOWN"
        month_folder = year_folder / "UNKNOWN"
    else:
        year_folder = DEST_BASE_DIR / file_date.strftime("%Y")
        month_folder = year_folder / file_date.strftime("%m")

    # Create directories if they don't exist.
    month_folder.mkdir(parents=True, exist_ok=True)

    # Set folder timestamps if a valid date exists.
    if file_date:
        set_folder_timestamp(year_folder, datetime(file_date.year, 1, 1))
        set_folder_timestamp(month_folder, datetime(file_date.year, int(file_date.strftime("%m")), 1))

    dest_file = month_folder / cleaned_name
    shutil.copy2(first_valid_file, dest_file)
    copied_hash = calculate_sha512(dest_file)
    if copied_hash != list(unique_hashes)[0]:
        log_message("Error: Checksum mismatch after copying!")
        # sys.exit(1)
        log_message("----------REPEAT----------")
        log_message("--------------------------")
        shutil.copy2(first_valid_file, dest_file)

        copied_hash = calculate_sha512(dest_file)
        if copied_hash != list(unique_hashes)[0]:
            log_message("Error: Checksum mismatch after copying!")
            log_message("----------ERROR AFTER REPEAT----------")
            sys.exit(1)

    # Update backup space statistics.
    backup_size = dest_file.stat().st_size
    total_backup_space += backup_size

    log_message(f"Backup successful: {first_valid_file} -> {dest_file}")

    # If deletion is enabled, delete all source files with the matching hash.
    if delete_sources:
        for source_file in file_group:
            source_path = Path(source_file)
            if source_path.exists():
                if calculate_sha512(source_path) == copied_hash:
                    try:
                        source_path.unlink()
                        deleted_files_count += 1
                        log_message(f"[DEL] Deleted source file: {source_path}")
                    except Exception as e:
                        log_message(f"Error deleting {source_path}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backup files while verifying checksums.")
    parser.add_argument(
        "--delete-sources",
        action="store_true",
        help="Delete source files after successful backup and checksum verification."
    )
    args = parser.parse_args()
    process_file_blocks(SOURCE_FILE, delete_sources=args.delete_sources)
