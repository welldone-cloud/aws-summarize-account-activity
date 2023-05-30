import argparse
import json
import os
import re
import sys

from aws_summarize_account_activity import generate_plot_files


EXPECTED_FILE_FORMAT_REGEX = "account_activity_(\\d+)_(\\d+).json"


if __name__ == "__main__":
    # Check runtime environment
    if sys.version_info[0] < 3:
        print("Python version 3 required")
        sys.exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file",
        required=True,
        type=argparse.FileType("r"),
        nargs=1,
        help="JSON file to generate plots for",
    )
    args = parser.parse_args()
    file_name = args.file[0]

    # Read source file
    file_name_without_path = os.path.basename(file_name.name)
    captures = re.fullmatch(EXPECTED_FILE_FORMAT_REGEX, file_name_without_path)
    if captures:
        account_id = captures.group(1)
        run_timestamp = captures.group(2)
    else:
        print("Unexpected file name received: {}".format(file_name_without_path))
        print("Expected pattern: {}".format(EXPECTED_FILE_FORMAT_REGEX))
        sys.exit(1)
    try:
        result_collection = json.load(file_name)
    except json.decoder.JSONDecodeError:
        print("Invalid JSON content")
        sys.exit(1)

    # Write plot files
    print("Generating plots")
    output_dir_name = "account_activity_{}_{}_plots".format(account_id, run_timestamp)
    generate_plot_files(result_collection, output_dir_name)
    print("Plot files written to {}".format(output_dir_name))
