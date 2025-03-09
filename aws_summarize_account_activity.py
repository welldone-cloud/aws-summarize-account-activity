#!/usr/bin/env python3

import argparse
import boto3
import botocore.config
import botocore.exceptions
import concurrent.futures
import datetime
import importlib.metadata
import json
import os
import packaging.requirements
import packaging.version
import pathlib
import sys
import traceback

from modules import cloudtrail_parser
from modules import cloudtrail_plotter


AWS_DEFAULT_REGION = "us-east-1"

BOTO_CLIENT_CONFIG = botocore.config.Config(
    retries={"total_max_attempts": 5, "mode": "standard"},
    user_agent_appid="aws-summarize-account-activity",
)

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_CLOUDTRAIL_LOG_RECORDS = 1000


def increase_result_collection_counter(result_section, category, key):
    """
    Increases the counter for the given key in the result collection structure by one. If the key does not exist yet,
    it is created with a value of one.
    Example invocation:
      increase_result_collection_counter("api_calls_by_region", "eu-central-1", "ec2.amazonaws.com:DescribeVolumes")
    """
    try:
        result_collection[result_section][category][key] += 1
    except KeyError:
        if category not in result_collection[result_section]:
            result_collection[result_section][category] = {}
        result_collection[result_section][category][key] = 1


def collect_cloudtrail_data_for_region(region):
    """
    Collects account activity recorded in CloudTrail for the given region. Adds the collected activity to the overall
    result collection. If configured, dumps a copy of the raw CloudTrail data fetched.
    """
    boto_session = boto3.Session(profile_name=args.profile, region_name=region)
    cloudtrail_client = boto_session.client("cloudtrail", config=BOTO_CLIENT_CONFIG)
    cloudtrail_paginator = cloudtrail_client.get_paginator("lookup_events")
    number_of_log_records_processed = -1
    if args.dump_raw_cloudtrail_data:
        dump_file = open(os.path.join(raw_cloudtrail_data_directory, "{}.jsonl".format(region)), "w")

    # Iterate through CloudTrail logs
    try:
        for response_page in cloudtrail_paginator.paginate(StartTime=from_timestamp, EndTime=run_timestamp):
            for event in response_page["Events"]:
                number_of_log_records_processed += 1
                log_record = json.loads(event["CloudTrailEvent"])

                # Show regular status messages
                if number_of_log_records_processed % SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_CLOUDTRAIL_LOG_RECORDS == 0:
                    msg = "Reading CloudTrail records from region {}".format(region)
                    if number_of_log_records_processed > 0:
                        msg += " (count: {}, currently at: {})".format(
                            number_of_log_records_processed,
                            event["EventTime"].astimezone(datetime.timezone.utc).replace(tzinfo=None),
                        )
                    print(msg)

                # Dump log record, if configured
                if args.dump_raw_cloudtrail_data:
                    dump_file.write("{}\n".format(json.dumps(log_record, separators=(",", ":"))))

                # Skip certain types of activity, if configured
                if args.activity_type != "ALL":
                    is_successful_api_call = cloudtrail_parser.is_successful_api_call(log_record)
                    if (args.activity_type == "SUCCESSFUL" and not is_successful_api_call) or (
                        args.activity_type == "FAILED" and is_successful_api_call
                    ):
                        continue

                # Extract log record details
                principal = cloudtrail_parser.get_principal_from_log_record(log_record)
                api_call = cloudtrail_parser.get_api_call_from_log_record(log_record)
                ip_address = cloudtrail_parser.get_ip_address_from_log_record(log_record)
                user_agent = cloudtrail_parser.get_user_agent_from_log_record(log_record)
                error_code = cloudtrail_parser.get_error_code_from_log_record(log_record)

                # Increase counters in the result collection
                increase_result_collection_counter("api_calls_by_principal", principal, api_call)
                increase_result_collection_counter("api_calls_by_region", region, api_call)
                increase_result_collection_counter("ip_addresses_by_principal", principal, ip_address)
                increase_result_collection_counter("user_agents_by_principal", principal, user_agent)
                if error_code:
                    increase_result_collection_counter("error_codes_by_principal", principal, error_code)

    except botocore.exceptions.ClientError as ex:
        error_message = ex.response["Error"]["Code"]
        print("Failed reading CloudTrail events from region {}: {}".format(region, error_message))
        result_collection["_metadata"]["regions_failed"][region] = error_message
        return

    except Exception as ex:
        print("Unexpected error in region {}.".format(region))
        print("Please report this as an issue along with the stack trace information.")
        print(traceback.format_exc())
        return

    finally:
        if args.dump_raw_cloudtrail_data:
            dump_file.close()

    print("Finished region {}".format(region))


def parse_argument_past_hours(val):
    """
    Argument validator.
    """
    hours = int(val)
    if not 1 <= hours <= 2160:
        raise argparse.ArgumentTypeError("Invalid value for argument")
    return hours


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
        "--activity-type",
        default="ALL",
        choices=["ALL", "SUCCESSFUL", "FAILED"],
        help="type of CloudTrail data to analyze: all API calls (default), only successful API calls, or only API calls that AWS declined with an error message",
    )
    parser.add_argument(
        "--dump-raw-cloudtrail-data",
        default=False,
        action="store_true",
        help="store a copy of all gathered CloudTrail data in JSONL format",
    )
    parser.add_argument(
        "--past-hours",
        default=336,
        type=parse_argument_past_hours,
        help="hours of CloudTrail data to look back and analyze, default: 336 (=14 days), minimum: 1, maximum: 2160 (=90 days)",
    )
    parser.add_argument(
        "--plot-results",
        default=False,
        action="store_true",
        help="generate PNG files that visualize the JSON output file",
    )
    parser.add_argument(
        "--profile",
        help="named AWS profile to use when running the command",
    )
    args = parser.parse_args()

    # Test for valid credentials
    try:
        boto_session = boto3.Session(profile_name=args.profile, region_name=AWS_DEFAULT_REGION)
    except botocore.exceptions.ProfileNotFound as ex:
        print("Error: {}".format(ex))
        sys.exit(1)
    sts_client = boto_session.client("sts", config=BOTO_CLIENT_CONFIG)
    try:
        sts_response = sts_client.get_caller_identity()
        account_id = sts_response["Account"]
        account_principal = sts_response["Arn"]
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)

    print("Analyzing account ID {}".format(account_id))

    # Get regions enabled in the account
    ec2_client = boto_session.client("ec2", config=BOTO_CLIENT_CONFIG)
    ec2_response = ec2_client.describe_regions(AllRegions=False)
    enabled_regions = sorted([region["RegionName"] for region in ec2_response["Regions"]])

    # Prepare result collection JSON structure
    run_timestamp = datetime.datetime.now(datetime.timezone.utc)
    run_timestamp_str = run_timestamp.strftime(TIMESTAMP_FORMAT)
    from_timestamp = run_timestamp - datetime.timedelta(hours=args.past_hours)
    from_timestamp_str = from_timestamp.strftime(TIMESTAMP_FORMAT)
    result_collection = {
        "_metadata": {
            "account_id": account_id,
            "account_principal": account_principal,
            "activity_type": args.activity_type,
            "cloudtrail_data_analyzed": {
                "from_timestamp": from_timestamp_str,
                "to_timestamp": run_timestamp_str,
            },
            "invocation": " ".join(sys.argv),
            "regions_enabled": enabled_regions,
            "regions_failed": {},
            "run_timestamp": run_timestamp_str,
        },
        "api_calls_by_principal": {},
        "api_calls_by_region": {},
        "ip_addresses_by_principal": {},
        "user_agents_by_principal": {},
        "error_codes_by_principal": {},
    }

    # Prepare results directories
    results_directory = os.path.join(os.path.relpath(os.path.dirname(__file__) or "."), "results")
    try:
        os.mkdir(results_directory)
    except FileExistsError:
        pass
    if args.dump_raw_cloudtrail_data:
        raw_cloudtrail_data_directory = os.path.join(
            results_directory, "account_activity_{}_{}_raw_cloudtrail_data".format(account_id, run_timestamp_str)
        )
        os.mkdir(raw_cloudtrail_data_directory)
    if args.plot_results:
        plots_directory = os.path.join(
            results_directory, "account_activity_{}_{}_plots".format(account_id, run_timestamp_str)
        )
        os.mkdir(plots_directory)

    # Collect CloudTrail data for all enabled regions
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for region in enabled_regions:
            executor.submit(collect_cloudtrail_data_for_region, region)

    # Write results and print result locations
    result_file = os.path.join(results_directory, "account_activity_{}_{}.json".format(account_id, run_timestamp_str))
    with open(result_file, "w") as out_file:
        json.dump(result_collection, out_file, indent=2, sort_keys=True)
    print("Output file written to {}".format(result_file))
    if args.dump_raw_cloudtrail_data:
        print("Raw CloudTrail data written to {}".format(raw_cloudtrail_data_directory))
    if args.plot_results:
        if not result_collection["api_calls_by_principal"]:
            print("No API call activity to plot")
        else:
            print("Generating plots")
            cloudtrail_plotter.generate_plot_files(result_collection, plots_directory)
            print("Plot files written to {}".format(plots_directory))
