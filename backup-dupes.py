#!/usr/bin/python

import argparse
import hashlib
import json
import shutil
import sys
import re
import os
import subprocess
import logging
import time  # For measuring total process time
from pathlib import Path
from datetime import datetime
from PIL import Image

# Use fdupes for create the file file_list.txt
# time sudo fdupes -r /path/to/find/dupes >file_list.txt

# Global statistics for backup mode
total_duplicate_space = 0
total_backup_space = 0
deleted_files_count = 0

# New global counters for backup mode
total_backup_file_count = 0
failed_backup_count = 0

# Files and directories
SOURCE_FILE = "file_list.txt"  # Change this to your actual text file
DEST_BASE_DIR = Path("/backup")  # Base backup folder
BACKUP_DATA_FILE = "backup_data.json"  # JSON file to store backup records

# Create a dynamic log file name based on today's date.
LOG_FILE = "backup." + datetime.now().strftime("%Y%m%d") + ".log"

# Regex patterns for date extraction and cleaning filenames.
DATE_PATTERN = re.compile(r"PXL_(\d{8})")  # Extracts YYYYMMDD from filenames
TRASHED_PATTERN = re.compile(r"\.trashed-\d+-")  # Matches `.trashed-*` prefix

# Setup logging to file and console.
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
def log_message(message):
    print(message)
    logging.info(message)

def get_human_size(bytes_size):
    """Convert bytes to a human-readable format."""
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
    """Calculate the SHA-512 checksum of a file."""
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

def load_backup_data():
    """Load existing backup records from the JSON file."""
    if Path(BACKUP_DATA_FILE).exists():
        try:
            with open(BACKUP_DATA_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            log_message(f"Error reading {BACKUP_DATA_FILE}: {e}")
    return []

def save_backup_data(data):
    """Save backup records to the JSON file."""
    try:
        with open(BACKUP_DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        log_message(f"Error writing to {BACKUP_DATA_FILE}: {e}")

def process_file_blocks(file_path, delete_sources=False, check_backup=False):
    """Process the file list, group files by empty lines, and perform backup or check mode."""
    overall_start_time = time.time()  # Start total processing time

    if check_backup:
        check_backup_data()
        total_elapsed = time.time() - overall_start_time
        minutes = int(total_elapsed // 60)
        seconds = int(total_elapsed % 60)
        log_message(f"Total check time: {minutes} minutes, {seconds} seconds")
        return

    with open(file_path, "r") as f:
        lines = [line.strip() for line in f.readlines()]

    blocks = []
    current_block = []
    for line in lines:
        if not line:
            if current_block:
                blocks.append(current_block)
                current_block = []
        else:
            current_block.append(line)
    if current_block:
        blocks.append(current_block)

    # Load existing backup data (if any).
    backup_records = load_backup_data()

    for block in blocks:
        record = validate_and_backup(block, delete_sources)
        if record:
            backup_records.append(record)

    # Save the updated backup records.
    save_backup_data(backup_records)

    total_elapsed = time.time() - overall_start_time
    minutes = int(total_elapsed // 60)
    seconds = int(total_elapsed % 60)
    log_message("\n==== Backup Statistics ====")
    log_message(f"Total space occupied by duplicate files: {get_human_size(total_duplicate_space)}")
    log_message(f"Total space occupied by backed-up files: {get_human_size(total_backup_space)}")
    log_message(f"Total files processed: {total_backup_file_count}")
    log_message(f"Failed backup count: {failed_backup_count}")
    if delete_sources:
        log_message(f"Total number of source files deleted: {deleted_files_count}")
    log_message(f"Total process time: {minutes} minutes, {seconds} seconds")
    log_message("Backup process completed successfully.")

def validate_and_backup(file_group, delete_sources):
    """Normal backup: Validate and copy one file from a group.
       Returns a record (dict) for the JSON file if successful, else None."""
    global total_duplicate_space, total_backup_space, deleted_files_count, total_backup_file_count, failed_backup_count

    if not file_group:
        return None

    # Calculate checksums for all files in the block.
    checksums = {}
    for file in file_group:
        file_path = Path(file)
        if not file_path.exists():
            log_message(f"Error: File not found - {file}")
            continue
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
        return None

    unique_hashes = set(checksums.values())
    if len(unique_hashes) > 1:
        log_message("Error: Files in the same block have different checksums!")
        return None

    # Update duplicate space statistics.
    duplicate_size = sum(Path(f).stat().st_size for f in checksums if Path(f).exists())
    total_duplicate_space += duplicate_size

    # Instead of using the first file, choose the file with the largest size.
    source_files = list(checksums.keys())
    chosen_source = max(source_files, key=lambda f: Path(f).stat().st_size)
    first_valid_file = chosen_source  # Use this as the source for backup

    cleaned_name = clean_filename(Path(first_valid_file).name)

    # Determine file date: try to extract from filename; for MP4 override with metadata.
    file_date = extract_date_from_filename(cleaned_name)
    if first_valid_file.lower().endswith(".mp4"):
        mp4_date = extract_mp4_creation_time(first_valid_file)
        if mp4_date:
            file_date = mp4_date
            log_message(f"Restored date from metadata for {cleaned_name}: {file_date.strftime('%Y/%m/%d %H:%M:%S')}")

    if not file_date:
        log_message(f"Error: Could not extract date for {cleaned_name}. Backing up to 'UNKNOWN' folder.")
        year_folder = DEST_BASE_DIR / "UNKNOWN"
        month_folder = year_folder / "UNKNOWN"
        backup_folder_record = "UNKNOWN/UNKNOWN"
    else:
        year_folder = DEST_BASE_DIR / file_date.strftime("%Y")
        month_folder = year_folder / file_date.strftime("%m")
        backup_folder_record = f"{file_date.strftime('%Y')}/{file_date.strftime('%m')}"

    month_folder.mkdir(parents=True, exist_ok=True)
    if file_date:
        required_year = datetime(file_date.year, 1, 1)
        current_year_ts = os.stat(year_folder).st_mtime
        if abs(current_year_ts - required_year.timestamp()) > 1:
            set_folder_timestamp(year_folder, required_year)
        required_month = datetime(file_date.year, file_date.month, 1)
        current_month_ts = os.stat(month_folder).st_mtime
        if abs(current_month_ts - required_month.timestamp()) > 1:
            set_folder_timestamp(month_folder, required_month)
    else:
        # Fallback: use the first day of the current month
        current = datetime.now()
        required_month = datetime(current.year, current.month, 1)
        current_month_ts = os.stat(month_folder).st_mtime
        if abs(current_month_ts - required_month.timestamp()) > 1:
            set_folder_timestamp(month_folder, required_month)

    # ----- NEW LOGIC FOR VARIANT HANDLING BASED ON FILE SIZE -----
    source_size = Path(first_valid_file).stat().st_size
    variant_used = "default"

    default_dest = month_folder / cleaned_name

    # Set the source hash (all files in the block have the same hash)
    # Define the source hash from the unique checksum
    # Calculate the unique checksum for the source file.
    source_hash = list(unique_hashes)[0]
    
    default_dest = month_folder / cleaned_name
    if default_dest.exists():
        existing_hash = calculate_sha512(default_dest)
        if existing_hash != source_hash:
            log_message(f"Default destination {default_dest} exists but checksum mismatch detected.")
            # Use a variant folder since default file is not identical.
            variant_found = None
            for i in range(1, 100):  # allow up to 99 variants
                variant_code = f"dup-{i:02d}"
                candidate_folder = month_folder / variant_code
                candidate_folder.mkdir(parents=True, exist_ok=True)
                set_folder_timestamp(candidate_folder, required_month)
                candidate_file = candidate_folder / cleaned_name
                if candidate_file.exists():
                    candidate_hash = calculate_sha512(candidate_file)
                    if candidate_hash == source_hash:
                        log_message(f"File already exists at {candidate_file} with matching checksum.")
                        dest_file = candidate_file
                        variant_found = variant_code
                        break
                    else:
                        continue
                else:
                    dest_file = candidate_file
                    variant_found = variant_code
                    log_message(f"Copying to variant folder: {variant_code} due to checksum mismatch at default destination.")
                    break
            if variant_found is None:
                log_message("Error: Could not determine a candidate variant folder for backup.")
                failed_backup_count += 1
                return None
            else:
                variant_used = variant_found
        else:
            log_message(f"Default destination {default_dest} exists and matches in checksum.")
            dest_file = default_dest
            variant_used = "default"
    else:
        dest_file = default_dest
        variant_used = "default"

    # If destination file does not exist, perform the copy and update file timestamp.
    if not dest_file.exists():
        shutil.copy2(first_valid_file, dest_file)
        if file_date:
            os.utime(dest_file, (file_date.timestamp(), file_date.timestamp()))

    # ----- END NEW LOGIC -----

    total_backup_file_count += 1
    copied_hash = calculate_sha512(dest_file)
    if copied_hash != list(unique_hashes)[0]:
        log_message("Error: Checksum mismatch after copying!")
        log_message("----------REPEAT----------")
        orig_size = Path(first_valid_file).stat().st_size / (1024 * 1024)
        backup_size = dest_file.stat().st_size / (1024 * 1024)
        log_message(f"Before repeat: Checksum mismatch for file. Original size: {orig_size:.2f} MB, Backup size: {backup_size:.2f} MB")
        shutil.copy2(first_valid_file, dest_file)
        if file_date:
            os.utime(dest_file, (file_date.timestamp(), file_date.timestamp()))
        copied_hash = calculate_sha512(dest_file)
        if copied_hash != list(unique_hashes)[0]:
            orig_size = Path(first_valid_file).stat().st_size / (1024 * 1024)
            backup_size = dest_file.stat().st_size / (1024 * 1024)
            log_message(f"Error after repeat: Checksum mismatch for file. Original size: {orig_size:.2f} MB, Backup size: {backup_size:.2f} MB")
            failed_backup_count += 1
            return None
        else:
            log_message(f"Repeat copy successful: {first_valid_file} -> {dest_file}")
    else:
        log_message(f"Copy successful: {first_valid_file} -> {dest_file}")

    backup_size = dest_file.stat().st_size
    total_backup_space += backup_size
    log_message(f"Backup successful: {first_valid_file} -> {dest_file}")

    if delete_sources:
        for source_file in file_group:
            source_path = Path(source_file)
            if source_path.exists() and calculate_sha512(source_path) == copied_hash:
                try:
                    source_path.unlink()
                    deleted_files_count += 1
                    log_message(f"Deleted source file: {source_path}")
                except Exception as e:
                    log_message(f"Error deleting {source_path}: {e}")

    # Update backup folder record if a variant folder was used.
    if variant_used != "default":
        backup_folder_record = backup_folder_record + "/" + variant_used

    return {
        "backup_path": backup_folder_record,
        "name": cleaned_name,
        "sha512sum": copied_hash,
        "file_size": source_size,
        "variant": variant_used
    }

def check_backup_data():
    """Read backup_data.json and check each backup file's SHA-512 sum while logging speed statistics and failures."""
    records = load_backup_data()
    if not records:
        log_message("No backup records found in JSON file.")
        return

    log_message("==== Starting Backup Data Check ====")
    overall_start_time = time.time()
    total_size_checked = 0
    file_count = 0
    failed_count = 0  # Count of files with checksum failures

    for record in records:
        file_count += 1
        backup_path = record.get("backup_path", "")
        name = record.get("name", "")
        expected_hash = record.get("sha512sum", "")
        full_path = DEST_BASE_DIR / backup_path / name

        log_message(f"Checking file: {full_path}")
        if not full_path.exists():
            log_message(f"File missing: {full_path}")
            failed_count += 1
            continue

        file_size = full_path.stat().st_size
        total_size_checked += file_size

        file_start_time = time.time()
        current_hash = calculate_sha512(full_path)
        file_end_time = time.time()

        elapsed = file_end_time - file_start_time
        speed_file = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        overall_elapsed = file_end_time - overall_start_time
        cumulative_speed = (total_size_checked / (1024 * 1024)) / overall_elapsed if overall_elapsed > 0 else 0

        log_message(f"Time for current file: {elapsed:.2f} sec, average speed: {speed_file:.2f} MB/sec")
        if current_hash != expected_hash:
            log_message(f"Checksum mismatch for {full_path} (expected {expected_hash}, got {current_hash}) (speed: {speed_file:.2f} MB/sec)")
            failed_count += 1
        else:
            log_message(f"File OK: {full_path} (speed: {speed_file:.2f} MB/sec)")
        log_message(f"Cumulative average speed so far: {cumulative_speed:.2f} MB/sec\n")

    final_elapsed = time.time() - overall_start_time
    overall_speed = (total_size_checked / (1024 * 1024)) / final_elapsed if final_elapsed > 0 else 0
    log_message("==== Backup Check Completed ====")
    log_message(f"Total files checked: {file_count}")
    log_message(f"Total failed files: {failed_count}")
    log_message(f"Total time: {final_elapsed:.2f} sec, overall average speed: {overall_speed:.2f} MB/sec")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backup files while verifying checksums, update timestamps, and optionally delete sources or check backups.")
    parser.add_argument(
        "--delete-sources",
        action="store_true",
        help="Delete source files after successful backup and checksum verification."
    )
    parser.add_argument(
        "--check-backup",
        action="store_true",
        help="Read the backup JSON file and check backed-up files' checksums (read-only)."
    )
    args = parser.parse_args()
    process_file_blocks(SOURCE_FILE, delete_sources=args.delete_sources, check_backup=args.check_backup)
