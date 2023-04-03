import argparse
import boto3
import botocore.config
import concurrent.futures
import datetime
import json
import sys


AWS_DEFAULT_REGION = "us-east-1"

BOTO_CONFIG = botocore.config.Config(
    retries={"total_max_attempts": 5, "mode": "standard"}
)

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_ENTRIES = 1000


def get_cloudtrail_entries_from_region(boto_session, region, from_timestamp, to_timestamp):
    """
    Returns a tuple describing the region and the regional activity recorded in CloudTrail, for the given
    region and timeframe: (str(region), dict(principal) -> dict(api_call) -> int(count))
    """
    cloudtrail_client = boto_session.client("cloudtrail", config=BOTO_CONFIG, region_name=region)
    cloudtrail_paginator = cloudtrail_client.get_paginator("lookup_events")
    response_iterator = cloudtrail_paginator.paginate(StartTime=from_timestamp, EndTime=to_timestamp)

    cloudtrail_entries = {}
    number_of_cloudtrail_entries_processed = 0
    for response_page in response_iterator:
        for event in response_page["Events"]:
            if number_of_cloudtrail_entries_processed % SHOW_STATUS_MESSAGE_AFTER_NUMBER_OF_ENTRIES == 0:
                print("Reading data from region {}".format(region))

            event_detail = json.loads(event["CloudTrailEvent"])

            # Extract event details: principal and api_call
            if "arn" in event_detail["userIdentity"]:
                principal = event_detail["userIdentity"]["arn"]
            elif "invokedBy" in event_detail["userIdentity"]:
                principal = event_detail["userIdentity"]["invokedBy"]
            elif "accountId" in event_detail["userIdentity"]:
                principal = event_detail["userIdentity"]["accountId"]
            elif "principalId" in event_detail["userIdentity"]:
                principal = "{}:{}".format(
                    event_detail["userIdentity"]["type"], event_detail["userIdentity"]["principalId"]
                )
            else:
                principal = event_detail["userIdentity"]["type"]

            api_call = "{}:{}".format(event_detail["eventSource"], event_detail["eventName"])

            # Add to regional result collection
            try:
                cloudtrail_entries[principal][api_call] += 1
            except KeyError:
                if principal not in cloudtrail_entries:
                    cloudtrail_entries[principal] = {}
                if api_call not in cloudtrail_entries[principal]:
                    cloudtrail_entries[principal][api_call] = 1

            number_of_cloudtrail_entries_processed += 1

    print("Finished region {}".format(region))
    return (region, cloudtrail_entries)


def add_cloudtrail_entries_to_result_collection(regional_cloudtrail_activity, result_collection):
    """
    Adds the given tuple describing regional activity recorded in CloudTrail to the overall collection of results.
    """
    region, cloudtrail_entries = regional_cloudtrail_activity
    for principal in cloudtrail_entries:
        for api_call in cloudtrail_entries[principal]:
            count = cloudtrail_entries[principal][api_call]

            try:
                result_collection["activity_by_principal"][principal][api_call] += count
            except KeyError:
                if principal not in result_collection["activity_by_principal"]:
                    result_collection["activity_by_principal"][principal] = {}
                if api_call not in result_collection["activity_by_principal"][principal]:
                    result_collection["activity_by_principal"][principal][api_call] = count

            try:
                result_collection["activity_by_region"][region][api_call] += count
            except KeyError:
                if region not in result_collection["activity_by_region"]:
                    result_collection["activity_by_region"][region] = {}
                if api_call not in result_collection["activity_by_region"][region]:
                    result_collection["activity_by_region"][region][api_call] = count


def parse_argument_past_hours(val):
    """
    Argument validator.
    """
    hours = int(val)
    if not 1 <= hours <= 2160:
        raise argparse.ArgumentTypeError("Invalid value for argument")
    return hours


def parse_argument_threads(val):
    """
    Argument validator.
    """
    threads = int(val)
    if not 1 <= threads <= 32:
        raise argparse.ArgumentTypeError("Invalid value for argument")
    return threads


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
        "--threads",
        required=False,
        nargs=1,
        default=[8],
        type=parse_argument_threads,
        help="number of threads to use (one thread analyzes one region), default: 8, minimum: 1, maximum: 32",
    )
    parser.add_argument(
        "--profile",
        required=False,
        nargs=1,
        help="named profile to use when running the command",
    )
    args = parser.parse_args()
    past_hours = args.past_hours[0]
    threads = args.threads[0]
    profile = args.profile[0] if args.profile else None
    boto_session = boto3.session.Session(profile_name=profile)

    # Test for valid credentials
    sts_client = boto_session.client("sts", config=BOTO_CONFIG, region_name=AWS_DEFAULT_REGION)
    try:
        sts_response = sts_client.get_caller_identity()
        print("Analyzing account ID {}".format(sts_response["Account"]))
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)

    # Get regions enabled in the account
    ec2_client = boto_session.client("ec2", config=BOTO_CONFIG, region_name=AWS_DEFAULT_REGION)
    ec2_response = ec2_client.describe_regions(AllRegions=False)
    enabled_regions = sorted([region["RegionName"] for region in ec2_response["Regions"]])

    # Prepare result collection structure
    run_timestamp = datetime.datetime.utcnow()
    run_timestamp_str = run_timestamp.strftime(TIMESTAMP_FORMAT)
    from_timestamp = run_timestamp - datetime.timedelta(hours=past_hours)
    from_timestamp_str = from_timestamp.strftime(TIMESTAMP_FORMAT)
    result_collection = {
        "_metadata": {
            "account_id": sts_response["Account"],
            "account_principal": sts_response["Arn"],
            "cloudtrail_data_analyzed": {
                "from_timestamp": from_timestamp_str,
                "to_timestamp": run_timestamp_str,
            },
            "regions": enabled_regions,
            "run_timestamp": run_timestamp_str,
        },
        "activity_by_principal": {},
        "activity_by_region": {},
    }

    # Collect CloudTrail data from all enabled regions
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for region in enabled_regions:
            future = executor.submit(
                get_cloudtrail_entries_from_region,
                boto_session,
                region,
                from_timestamp,
                run_timestamp,
            )
            futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            add_cloudtrail_entries_to_result_collection(future.result(), result_collection)

    # Write result file
    output_file_name = "account_activity_{}_{}.json".format(sts_response["Account"], run_timestamp_str)
    with open(output_file_name, "w") as out_file:
        json.dump(result_collection, out_file, indent=2, sort_keys=True)

    print("Output file written to {}".format(output_file_name))
