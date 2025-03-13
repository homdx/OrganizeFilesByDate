import os

#This script is designed to process groups of duplicate files (as specified in an input text file) and ensure that only one copy remains on disk for each group. The input file is expected to have duplicate groups separated by blank lines, with each group containing one or more file paths. The script performs the following main tasks:

#    Calculate Total Duplicate Space: It sums up the sizes of all files across duplicate groups (if they exist on disk).
#    Deduplicate Within Each Group: It identifies unique physical files even if they are referred to by different paths.
#    Select a Candidate to Keep: It applies criteria to choose one “clean” file from each group.
#    Delete the Other Files: It deletes all duplicate files in the group except for the chosen candidate.
#    Print a Summary: It reports the total space processed, freed space, and any errors encountered.
#    Be careful when removing duplicate files after running:
#    fdupes -r /path/to/search/duples > find-duples.txt
#    If you're sure, uncomment the line with: os.remove(fp)


def sizeof_fmt(num, suffix='B'):
    """Convert bytes to human-readable format."""
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} Yi{suffix}"

def process_duplicates(input_file):
    total_duplicate_space = 0
    freed_space = 0
    processed_files = 0
    errors = 0

    with open(input_file, 'r') as f:
        content = f.read()

    # Each duplicate group is assumed to be separated by blank lines.
    blocks = [b.splitlines() for b in content.split('\n\n') if b.strip()]
    print(f"Processing {len(blocks)} duplicate groups...\n")

    # First pass: Sum total size of all files (if they exist)
    for block in blocks:
        for file_path in block:
            file_path = file_path.strip()
            if file_path and os.path.exists(file_path):
                try:
                    total_duplicate_space += os.path.getsize(file_path)
                except Exception:
                    pass

    # Second pass: Process each duplicate group.
    for idx, block in enumerate(blocks, 1):
        # Remove blank lines and trim spaces.
        file_paths = [p.strip() for p in block if p.strip()]
        if not file_paths:
            continue

        # Build a mapping of real (canonical) path to a chosen file path.
        # This helps if the same file appears with different path notations.
        unique_files = {}
        for fp in file_paths:
            if os.path.exists(fp):
                real_fp = os.path.realpath(fp)
                # If already seen, keep the one with the shorter full path.
                if real_fp in unique_files:
                    if len(fp) < len(unique_files[real_fp]):
                        unique_files[real_fp] = fp
                else:
                    unique_files[real_fp] = fp

        unique_list = list(unique_files.values())
        # If only one unique file exists, leave it untouched.
        if len(unique_list) < 2:
            continue

        # Candidate selection: choose the file with the fewest directory levels,
        # and if tied, the one with the shorter overall path.
        candidate = min(unique_list, key=lambda x: (x.count(os.sep), len(x)))
        print(f"Group {idx}: Keeping '{candidate}' and deleting others.")

        # Delete all unique files in this group except the candidate.
        for fp in unique_list:
            if fp == candidate:
                continue
            try:
                file_size = os.path.getsize(fp)
#                os.remove(fp)
                freed_space += file_size
                processed_files += 1
                print(f"Group {idx}: Deleted {sizeof_fmt(file_size)} - '{fp}'")
            except Exception as e:
                print(f"Group {idx}: Error deleting '{fp}': {str(e)}")
                errors += 1
            print("---------------------")

    # Print summary.
    print("\n=== Operation Summary ===")
    print(f"Total duplicate groups processed: {len(blocks)}")
    print(f"Total files deleted: {processed_files}")
    print(f"Errors encountered: {errors}\n")
    print(f"Total duplicate space (all copies): {sizeof_fmt(total_duplicate_space)}")
    print(f"Space freed: {sizeof_fmt(freed_space)}")
    print(f"Remaining duplicate space: {sizeof_fmt(total_duplicate_space - freed_space)}")

if __name__ == "__main__":
    input_file = "find-duples.txt"
    process_duplicates(input_file)
