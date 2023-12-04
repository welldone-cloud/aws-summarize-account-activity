import argparse
import boto3
import botocore.config
import concurrent.futures
import datetime
import json
import sys

from modules import cloudtrail_parser
from modules import cloudtrail_plotter


AWS_DEFAULT_REGION = "us-east-1"

BOTO_CLIENT_CONFIG = botocore.config.Config(retries={"total_max_attempts": 5, "mode": "standard"})

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_CLOUDTRAIL_ENTRIES = 1000


def get_cloudtrail_entries_for_region(region, from_timestamp, to_timestamp):
    """
    Returns a nested dict describing the activity recorded in CloudTrail, for the given region and timeframe:
    dict[principal][api_call] = count
    """
    cloudtrail_entries = {}
    boto_session = boto3.session.Session(profile_name=profile, region_name=region)
    cloudtrail_client = boto_session.client("cloudtrail", config=BOTO_CLIENT_CONFIG)

    cloudtrail_paginator = cloudtrail_client.get_paginator("lookup_events")
    number_of_cloudtrail_entries_processed = 0
    for response_page in cloudtrail_paginator.paginate(StartTime=from_timestamp, EndTime=to_timestamp):
        for entry in response_page["Events"]:
            if number_of_cloudtrail_entries_processed % SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_CLOUDTRAIL_ENTRIES == 0:
                msg = "Reading CloudTrail records from region {}".format(region)
                if number_of_cloudtrail_entries_processed > 0:
                    msg += " (collected: {})".format(number_of_cloudtrail_entries_processed)
                print(msg)
            number_of_cloudtrail_entries_processed += 1

            log_record = json.loads(entry["CloudTrailEvent"])
            if skip_unsuccessful_api_calls and not cloudtrail_parser.is_successful_api_call(log_record):
                continue
            principal = cloudtrail_parser.get_principal_from_log_record(log_record)
            api_call = cloudtrail_parser.get_api_call_from_log_record(log_record)

            # Add to result structure
            try:
                cloudtrail_entries[principal][api_call] += 1
            except KeyError:
                if principal not in cloudtrail_entries:
                    cloudtrail_entries[principal] = {}
                if api_call not in cloudtrail_entries[principal]:
                    cloudtrail_entries[principal][api_call] = 1

    print("Finished region {}".format(region))
    return cloudtrail_entries


def add_cloudtrail_entries_to_result_collection(region, regional_cloudtrail_activity):
    """
    Adds the given regional activity recorded in CloudTrail to the overall result collection.
    """
    for principal in regional_cloudtrail_activity:
        for api_call in regional_cloudtrail_activity[principal]:
            count = regional_cloudtrail_activity[principal][api_call]

            # Add to principal results
            try:
                result_collection["api_calls_by_principal"][principal][api_call] += count
            except KeyError:
                if principal not in result_collection["api_calls_by_principal"]:
                    result_collection["api_calls_by_principal"][principal] = {}
                if api_call not in result_collection["api_calls_by_principal"][principal]:
                    result_collection["api_calls_by_principal"][principal][api_call] = count

            # Add to regional results
            try:
                result_collection["api_calls_by_region"][region][api_call] += count
            except KeyError:
                if region not in result_collection["api_calls_by_region"]:
                    result_collection["api_calls_by_region"][region] = {}
                if api_call not in result_collection["api_calls_by_region"][region]:
                    result_collection["api_calls_by_region"][region][api_call] = count


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
    if sys.version_info[0] < 3:
        print("Python version 3 required")
        sys.exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--past-hours",
        required=False,
        nargs=1,
        default=[336],
        type=parse_argument_past_hours,
        help="hours of CloudTrail data to look back and analyze, default: 336 (=14 days), minimum: 1, maximum: 2160 (=90 days)",
    )
    parser.add_argument(
        "--plot-results",
        required=False,
        default=False,
        action="store_true",
        help="generate PNG files that visualize the JSON output file",
    )
    parser.add_argument(
        "--profile",
        required=False,
        nargs=1,
        help="named AWS profile to use when running the command",
    )
    parser.add_argument(
        "--skip-unsuccessful-api-calls",
        required=False,
        default=False,
        action="store_true",
        help="do not include API call activity that AWS declined with an error message",
    )
    args = parser.parse_args()
    past_hours = args.past_hours[0]
    plot_results = args.plot_results
    profile = args.profile[0] if args.profile else None
    skip_unsuccessful_api_calls = args.skip_unsuccessful_api_calls

    boto_session = boto3.session.Session(profile_name=profile, region_name=AWS_DEFAULT_REGION)

    # Test for valid credentials
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

    # Prepare result collection structure
    run_timestamp = datetime.datetime.utcnow()
    run_timestamp_str = run_timestamp.strftime(TIMESTAMP_FORMAT)
    from_timestamp = run_timestamp - datetime.timedelta(hours=past_hours)
    from_timestamp_str = from_timestamp.strftime(TIMESTAMP_FORMAT)
    result_collection = {
        "_metadata": {
            "account_id": account_id,
            "account_principal": account_principal,
            "cloudtrail_data_analyzed": {
                "from_timestamp": from_timestamp_str,
                "to_timestamp": run_timestamp_str,
            },
            "regions_enabled": enabled_regions,
            "regions_failed": {},
            "run_timestamp": run_timestamp_str,
        },
        "api_calls_by_principal": {},
        "api_calls_by_region": {},
    }

    # Collect CloudTrail data from all enabled regions
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_region_mapping = {}
        for region in enabled_regions:
            future = executor.submit(
                get_cloudtrail_entries_for_region,
                region,
                from_timestamp,
                run_timestamp,
            )
            future_to_region_mapping[future] = region

        for future in concurrent.futures.as_completed(future_to_region_mapping.keys()):
            region = future_to_region_mapping[future]
            try:
                add_cloudtrail_entries_to_result_collection(region, future.result())
            except Exception as ex:
                error_message = ex.response["Error"]["Code"]
                print("Failed reading CloudTrail events from region {}: {}".format(region, error_message))
                result_collection["_metadata"]["regions_failed"][region] = error_message

    # Write JSON result file
    output_file_name = "account_activity_{}_{}.json".format(account_id, run_timestamp_str)
    with open(output_file_name, "w") as out_file:
        json.dump(result_collection, out_file, indent=2, sort_keys=True)
    print("Output file written to {}".format(output_file_name))

    # Write plot files, if configured
    if plot_results:
        print("Generating plots")
        output_directory_name = "account_activity_{}_{}_plots".format(account_id, run_timestamp_str)
        cloudtrail_plotter.generate_plot_files(result_collection, output_directory_name)
        print("Plot files written to {}".format(output_directory_name))
