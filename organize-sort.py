#!/bin/python3

import os
import shutil
import re
from datetime import datetime
import exifread
import time

def extract_date_from_filename(filename):
    """Extract the date from the filename in the format PXL_YYYYMMDD"""
    match = re.search(r'PXL_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})', filename)
    if match:
        year, month, day, hour, minute, second = match.groups()
        return year, month, day, hour, minute, second
    match = re.search(r'PXL_(\d{4})(\d{2})(\d{2})', filename)
    if match:
        year, month, day = match.groups()
        return year, month, day, '00', '00', '00'
    return None

def extract_date_from_exif(filepath):
    """Extract the date from EXIF metadata of an image."""
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)
            date_tag = tags.get('EXIF DateTimeOriginal') or tags.get('Image DateTime')
            if date_tag:
                date_str = str(date_tag)  # Format: YYYY:MM:DD HH:MM:SS
                date_part, time_part = date_str.split()
                year, month, day = date_part.split(':')
                hour, minute, second = time_part.split(':')
                return year, month, day, hour, minute, second
    except Exception as e:
        print(f"Error reading EXIF data from {filepath}: {e}")
    return None

def set_file_datetime(filepath, year, month, day, hour, minute, second):
    """Set the file's modification and access times based on extracted date and time."""
    try:
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        timestamp = time.mktime(dt.timetuple())
        os.utime(filepath, (timestamp, timestamp))
    except Exception as e:
        print(f"Error setting date/time for {filepath}: {e}")

def set_folder_datetime(folder_path, year, month, day):
    """Set the folder's modification date based on extracted date."""
    try:
        dt = datetime(int(year), int(month), int(day))
        timestamp = time.mktime(dt.timetuple())
        os.utime(folder_path, (timestamp, timestamp))
        print(f"Set date for folder {folder_path} to {year}-{month}-{day}")
    except Exception as e:
        print(f"Error setting date/time for folder {folder_path}: {e}")

def move_or_copy_file(src_path, dest_folder, action="copy", log_file=None):
    """Move or copy the file to the destination folder."""
    folder_created = False
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
        folder_created = True
        message = f"Created directory: {dest_folder}"
        print(message)
        if log_file:
            log_file.write(message + "\n")

    if folder_created:
        # Extract the year, month from the dest_folder structure
        path_parts = os.path.normpath(dest_folder).split(os.sep)
        if len(path_parts) >= 2:
            year, month = path_parts[-2], path_parts[-1]
            set_folder_datetime(dest_folder, year, month, '01')

    filename = os.path.basename(src_path)
    if filename.startswith(".trashed-"):
        filename = filename[len(".trashed-"):]  # Remove .trashed- prefix
    dest_path = os.path.join(dest_folder, filename)
    if action == "move":
        shutil.move(src_path, dest_path)
        message = f"Moved {src_path} to {dest_path}"
    else:
        shutil.copy2(src_path, dest_path)
        message = f"Copied {src_path} to {dest_path}"
    print(message)
    if log_file:
        log_file.write(message + "\n")
    return dest_path

def main(source_folder, destination_root, action="copy"):
    """Main function to organize files based on dates."""
    log_filename = datetime.now().strftime("%Y%m%d-result.txt")
    with open(log_filename, "w") as log_file:
        for root, _, files in os.walk(source_folder):
            for file in files:
                src_path = os.path.join(root, file)
                date_info = extract_date_from_filename(file)

                if not date_info:
                    # If no date in filename, try EXIF metadata
                    date_info = extract_date_from_exif(src_path)

                if date_info:
                    year, month, day, hour, minute, second = date_info
                    dest_folder = os.path.join(destination_root, year, month)
                    dest_path = move_or_copy_file(src_path, dest_folder, action=action, log_file=log_file)
                    set_file_datetime(dest_path, year, month, day, hour, minute, second)
                else:
                    message = f"Date not found for file: {os.path.relpath(src_path, source_folder)}"
                    print(message)
                    log_file.write(message + "\n")

if __name__ == "__main__":
    source_folder = input("Enter the source folder path: ")
    destination_root = input("Enter the destination root folder path: ")
    action = input("Enter action (move or copy): ").strip().lower()
    if action not in ["move", "copy"]:
        print("Invalid action. Defaulting to 'copy'.")
        action = "copy"
    main(source_folder, destination_root, action=action)
