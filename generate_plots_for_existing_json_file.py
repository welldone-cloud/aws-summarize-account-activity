#!/usr/bin/env python3

import argparse
import importlib.metadata
import json
import os
import packaging.requirements
import packaging.version
import pathlib
import re
import sys

from modules import cloudtrail_plotter


EXPECTED_FILE_FORMAT_REGEX = "account_activity_(\\d+)_(\\d+).json"


if __name__ == "__main__":
    # Check runtime environment
    if sys.version_info < (3, 10):
        print("Python version 3.10 or higher required")
        sys.exit(1)
    with open(os.path.join(pathlib.Path(__file__).parent, "requirements.txt"), "r") as requirements_file:
        for requirements_line in requirements_file.read().splitlines():
            requirement = packaging.requirements.Requirement(requirements_line)
            expected_version_specifier = requirement.specifier
            installed_version = packaging.version.parse(importlib.metadata.version(requirement.name))
            if installed_version not in expected_version_specifier:
                print("Unfulfilled requirement: {}".format(requirements_line))
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
        print("Error: Unexpected file name received: {}".format(file_name_without_path))
        print("Expected pattern: {}".format(EXPECTED_FILE_FORMAT_REGEX))
        sys.exit(1)
    try:
        result_collection = json.load(file_name)
    except json.decoder.JSONDecodeError:
        print("Error: Invalid JSON content")
        sys.exit(1)

    # Prepare results directories
    results_directory = os.path.join(os.path.relpath(os.path.dirname(__file__) or "."), "results")
    try:
        os.mkdir(results_directory)
    except FileExistsError:
        pass
    plots_directory = os.path.join(results_directory, "account_activity_{}_{}_plots".format(account_id, run_timestamp))
    try:
        os.mkdir(plots_directory)
    except FileExistsError:
        print("Error: Destination already exists: {}".format(plots_directory))
        sys.exit(1)

    # Write plot files
    if not result_collection["api_calls_by_principal"]:
        print("No API call activity to plot")
    else:
        print("Generating plots")
        cloudtrail_plotter.generate_plot_files(result_collection, plots_directory)
        print("Plot files written to {}".format(plots_directory))
