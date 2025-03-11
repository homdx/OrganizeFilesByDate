#!/usr/bin/python3

import argparse
import json
import hashlib
import sys
from pathlib import Path
from tqdm import tqdm


def log_message(message):
    print(message)


def calculate_sha512(file_path):
    """Calculate the SHA-512 checksum of a file."""
    try:
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha512.update(chunk)
        return sha512.hexdigest()
    except Exception as e:
        log_message(f"Error calculating SHA512 for {file_path}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Recursively scan a backup folder and generate a JSON file with backup records. Use this after manually cleaning the files in the backup folder to recreate a new JSON file."
    )
    parser.add_argument("--base-folder", required=True, help="Base folder to scan for backups")
    parser.add_argument("--output-json", required=True, help="Output JSON file for backup records")
    args = parser.parse_args()

    base_folder = Path(args.base_folder)
    if not base_folder.exists() or not base_folder.is_dir():
        log_message(f"Error: Base folder '{base_folder}' does not exist or is not a directory.")
        sys.exit(1)

    # Define supported file extensions
    supported_exts = {".jpg", ".jpeg", ".png", ".mov", ".mp4"}

    # Calculate the total size of files to process
    total_bytes = sum(
        file.stat().st_size for file in base_folder.rglob("*")
        if file.is_file() and file.suffix.lower() in supported_exts
    )

    records = []

    # Initialize tqdm progress bar
    with tqdm(total=total_bytes, unit="B", unit_scale=True, desc="Processing files") as progress_bar:
        # Recursively find all files under base_folder
        for file in base_folder.rglob("*"):
            if file.is_file() and file.suffix.lower() in supported_exts:
                try:
                    # Get the relative folder path (without the file name)
                    rel_dir = file.parent.relative_to(base_folder)
                except Exception as e:
                    log_message(f"Error computing relative path for {file}: {e}")
                    continue

                # Use forward slashes as separator
                backup_path = str(rel_dir).replace("\\", "/")
                file_name = file.name

                # Determine variant: if the last part of the relative path is in the form "dup-XX"
                variant = "default"
                if rel_dir.parts:
                    last_part = rel_dir.parts[-1]
                    if last_part.startswith("dup-") and len(last_part) == 6:
                        variant = last_part

                sha512sum = calculate_sha512(file)
                if sha512sum is None:
                    continue

                file_size = file.stat().st_size

                record = {
                    "backup_path": backup_path,
                    "name": file_name,
                    "sha512sum": sha512sum,
                    "file_size": file_size,
                    "variant": variant
                }
                records.append(record)

                # Update the progress bar
                progress_bar.update(file_size)

    # Write the records to the output JSON file
    output_path = Path(args.output_json)
    try:
        with output_path.open("w") as f:
            json.dump(records, f, indent=4)
        log_message(f"Backup JSON successfully written to '{output_path}'.")
    except Exception as e:
        log_message(f"Error writing output JSON: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
