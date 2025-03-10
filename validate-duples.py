#!/usr/bin/python

import sys
import os
import hashlib
import re
import subprocess
import logging
import time
import statistics
from pathlib import Path
from datetime import datetime
from PIL import Image

# Use fdupes to create the file_list.txt
# Run: time sudo fdupes -r /path/to/find/dupes > file_list.txt
# This script checks JPG and video files from file_list.txt and creates file_list-fixed.txt with good files. After that, use backup-dupes.py

# After this program has finished, you should look for differences between the removed broken files (only from text file):
# diff -Naur file_list-fixed.txt file_list.txt | grep '^-[^-]' | sed 's/^-//'

# Setup logging
LOG_FILE = "file_check_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def log_message(msg):
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as lf:
        lf.write(msg + "\n")

def format_seconds(sec):
    return time.strftime("%H:%M:%S", time.gmtime(sec))

def get_human_readable_size(num_bytes):
    for unit in ['B','KB','MB','GB','TB']:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"

def calculate_sha512(file_path):
    sha512 = hashlib.sha512()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha512.update(chunk)
        return sha512.hexdigest()
    except Exception as e:
        log_message(f"Error calculating SHA512 for {file_path}: {e}")
        return None

def check_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        with Image.open(file_path) as img:
            img.load()
        return True
    except Exception as e:
        log_message(f"Image check failed for {file_path}: {e}")
        return False

def check_video(file_path):
    """Check video integrity using QSV if available; fallback to CPU check."""
    log_message(f"Checking video: {file_path}")
    if USE_QSV:
        try:
            start = time.time()
            cmd_qsv = [
                "ffmpeg",
                "-init_hw_device", "qsv=hw",
                "-filter_hw_device", "hw",
                "-hwaccel", "qsv",
                "-v", "error",
                "-i", str(file_path),
                "-f", "null", "-"
            ]
            result_qsv = subprocess.run(cmd_qsv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            elapsed_qsv = time.time() - start
            if result_qsv.returncode == 0:
                log_message(f"  QSV Check: {elapsed_qsv:.2f}s - OK")
                return True
            else:
                log_message(f"  QSV Check: {elapsed_qsv:.2f}s - Error: {result_qsv.stderr.strip()} -- falling back to CPU check")
        except Exception as e:
            log_message(f"  QSV Check exception: {e} -- falling back to CPU check")
    try:
        start_cpu = time.time()
        cmd_cpu = [
            "ffmpeg",
            "-v", "error",
            "-i", str(file_path),
            "-f", "null", "-"
        ]
        result_cpu = subprocess.run(cmd_cpu, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        elapsed_cpu = time.time() - start_cpu
        status_cpu = "OK" if result_cpu.returncode == 0 else f"Error: {result_cpu.stderr.strip()}"
        log_message(f"  CPU Check: {elapsed_cpu:.2f}s - {status_cpu}")
        return result_cpu.returncode == 0
    except Exception as e:
        log_message(f"  CPU Check exception: {e}")
        return False

def is_supported(file_path):
    ext = Path(file_path).suffix.lower()
    return ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", 
                    ".mp4", ".mov", ".avi", ".mkv", ".flv", ".ts", ".mts"}

def check_file(file_path):
    p = Path(file_path)
    if not p.exists():
        log_message(f"File does not exist: {file_path}")
        return False
    if not is_supported(file_path):
        log_message(f"Skipping unsupported file: {file_path}")
        return False
    ext = p.suffix.lower()
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"}:
        return check_image(file_path)
    else:
        return check_video(file_path)

def process_block(block_lines):
    """
    Process a block (list of file paths) by:
      - Calculating SHA512 for each file.
      - Grouping files by hash.
      - Checking one representative file per group.
    Returns (good_files, broken_files, block_total_bytes).
    """
    group = {}
    sizes = {}
    for line in block_lines:
        file_path = line.strip()
        if not file_path:
            continue
        p = Path(file_path)
        try:
            size = p.stat().st_size
        except Exception:
            size = 0
        sizes[file_path] = size
        if not p.exists():
            key = "MISSING_" + file_path
            group.setdefault(key, []).append(file_path)
        elif not is_supported(file_path):
            key = "UNSUPPORTED_" + file_path
            group.setdefault(key, []).append(file_path)
        else:
            h = calculate_sha512(file_path)
            if h is None:
                key = "BROKEN_" + file_path
                group.setdefault(key, []).append(file_path)
            else:
                group.setdefault(h, []).append(file_path)
    good_files = []
    broken_files = []
    for key, files in group.items():
        if key.startswith("MISSING_") or key.startswith("UNSUPPORTED_") or key.startswith("BROKEN_"):
            broken_files.extend(files)
        else:
            rep = files[0]
            log_message(f"DEBUG: Checking representative for group {key} in block: {files}")
            if check_file(rep):
                good_files.extend(files)
            else:
                broken_files.extend(files)
    block_total = sum(sizes.values())
    return good_files, broken_files, block_total

def test_qsv():
    """Test if QSV hardware acceleration is available using a short nullsrc test."""
    try:
        cmd = [
            "ffmpeg",
            "-init_hw_device", "qsv=hw",
            "-filter_hw_device", "hw",
            "-hwaccel", "qsv",
            "-v", "error",
            "-f", "lavfi",
            "-i", "nullsrc=s=128x128",
            "-t", "1",
            "-f", "null", "-"
        ]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=15)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log_message("QSV test timed out.")
        return False

# Global flag for QSV usage.
USE_QSV = True

def main():
    global USE_QSV
    if test_qsv():
        log_message("QSV acceleration is available. Using QSV for video checks.")
        USE_QSV = True
    else:
        log_message("QSV acceleration is NOT available. Falling back to CPU for video checks.")
        USE_QSV = False

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <source_text_file>")
        sys.exit(1)
    source_txt = sys.argv[1]
    source_path = Path(source_txt)
    if not source_path.exists():
        print(f"Source file {source_txt} does not exist.")
        sys.exit(1)

    base_name = source_path.stem
    fixed_txt_filename = source_path.parent / f"{base_name}-fixed.txt"
    broken_txt_filename = source_path.parent / f"{base_name}-broken.txt"

    with source_path.open("r", encoding="utf-8") as f:
        content = f.read()

    blocks = [block.strip().splitlines() for block in content.strip().split("\n\n") if block.strip()]
    total_blocks = len(blocks)
    log_message(f"Total blocks found: {total_blocks}")

    total_bytes = 0
    for block in blocks:
        for file_path in block:
            file_path = file_path.strip()
            if file_path:
                try:
                    total_bytes += Path(file_path).stat().st_size
                except Exception:
                    pass

    fixed_blocks = []
    all_broken_files = []
    overall_good_total = 0     # Sum of sizes of all good files (each file in block)
    overall_backup_size = 0    # Sum of sizes for backup (one representative per block)
    block_good_sizes = []      # Sum of sizes of good files per block
    block_backup_sizes = []    # Size of chosen file per block
    processed_bytes = 0
    start_time = time.time()

    for i, block in enumerate(blocks, start=1):
        log_message(f"DEBUG: Starting processing block {i}/{total_blocks}. Block content: {block}")
        good_files, broken_files, block_total = process_block(block)
        fixed_blocks.append(good_files)
        all_broken_files.extend(broken_files)
        
        # Sum sizes of good files in this block.
        block_total_good = 0
        for gf in good_files:
            try:
                block_total_good += Path(gf).stat().st_size
            except Exception:
                pass
        block_good_sizes.append(block_total_good)
        overall_good_total += block_total_good

        # For backup size, choose one representative (largest good file) per block.
        if good_files:
            rep = max(good_files, key=lambda f: Path(f).stat().st_size)
            rep_size = Path(rep).stat().st_size
            block_backup_sizes.append(rep_size)
            overall_backup_size += rep_size
            log_message(f"Block {i}: Selected {rep} ({get_human_readable_size(rep_size)}) for backup size.")
        else:
            block_backup_sizes.append(0)
            log_message(f"Block {i}: No good files found for backup selection.")

        processed_bytes += block_total
        elapsed = time.time() - start_time
        current_rate = processed_bytes / elapsed if elapsed > 0 else 0
        remaining_bytes = total_bytes - processed_bytes
        estimated_remaining_time = remaining_bytes / current_rate if current_rate > 0 else 0

        log_message(f"Block {i}: {len(good_files)} good, {len(broken_files)} broken; Block good size: {get_human_readable_size(block_total_good)}")
        log_message(f"[{format_seconds(estimated_remaining_time)}] remain. Working time [{format_seconds(elapsed)}]\n")

    with open(fixed_txt_filename, "w", encoding="utf-8") as f:
    # Only join blocks that contain at least one file.
        output = "\n\n".join("\n".join(block) for block in fixed_blocks if block)
        f.write(output)


    log_message(f"Fixed file list created: {fixed_txt_filename}")

    # Write broken file list.
    with open(broken_txt_filename, "w", encoding="utf-8") as f:
        for file_path in all_broken_files:
            f.write(file_path + "\n")
    log_message(f"Broken files list created: {broken_txt_filename}")

    overall_time = time.time() - start_time
    log_message("\n==== Summary ====")
    log_message(f"Total size of all good files: {get_human_readable_size(overall_good_total)}")
    log_message(f"Overall backup size (one representative per block): {get_human_readable_size(overall_backup_size)}")
    for i, size in enumerate(block_good_sizes, start=1):
        log_message(f"Block {i} total good files size: {get_human_readable_size(size)}")
    for i, size in enumerate(block_backup_sizes, start=1):
        log_message(f"Block {i} backup file size: {get_human_readable_size(size)}")
    log_message(f"Total processing time: {format_seconds(overall_time)}")

if __name__ == "__main__":
    main()
