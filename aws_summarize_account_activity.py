import argparse
import boto3
import botocore.config
import concurrent.futures
import datetime
import json
import matplotlib.pyplot as plt
import os
import string
import sys


AWS_DEFAULT_REGION = "us-east-1"

BOTO_CONFIG = botocore.config.Config(retries={"total_max_attempts": 5, "mode": "standard"})

PLOT_CANVAS_SIZE = (14, 8)

PLOT_MAX_ITEMS = 50

PLOT_MAX_LENGTH_FILE_STEM = 250

PLOT_MAX_LENGTH_X_AXIS_LABELS = 85

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
                result_collection["api_calls_by_principal"][principal][api_call] += count
            except KeyError:
                if principal not in result_collection["api_calls_by_principal"]:
                    result_collection["api_calls_by_principal"][principal] = {}
                if api_call not in result_collection["api_calls_by_principal"][principal]:
                    result_collection["api_calls_by_principal"][principal][api_call] = count

            try:
                result_collection["api_calls_by_region"][region][api_call] += count
            except KeyError:
                if region not in result_collection["api_calls_by_region"]:
                    result_collection["api_calls_by_region"][region] = {}
                if api_call not in result_collection["api_calls_by_region"][region]:
                    result_collection["api_calls_by_region"][region][api_call] = count


def generate_plot_files(data, plots_dir):
    """
    Generates plots that represent the given CloudTrail data and writes them to the given directory as PNG files.
    """
    os.mkdir(plots_dir)
    principals_dir = os.path.join(plots_dir, "principals")
    os.mkdir(principals_dir)
    regions_dir = os.path.join(plots_dir, "regions")
    os.mkdir(regions_dir)

    # Generate principal summary plot
    total_api_calls_per_principal = {}
    for principal in data["api_calls_by_principal"]:
        total_api_calls_per_principal[principal] = 0
        for api_call in data["api_calls_by_principal"][principal]:
            total_api_calls_per_principal[principal] += data["api_calls_by_principal"][principal][api_call]
    x_axis, y_axis = dict_to_sorted_tuples(total_api_calls_per_principal, PLOT_MAX_ITEMS)
    x_axis = tuple(truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
    title = "API calls per principal (max. entries: {})".format(PLOT_MAX_ITEMS)
    output_file = os.path.join(plots_dir, "summary_principals.png")
    write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate principal detail plots
    for principal in data["api_calls_by_principal"]:
        principal_data = data["api_calls_by_principal"][principal]
        x_axis, y_axis = dict_to_sorted_tuples(principal_data, PLOT_MAX_ITEMS)
        x_axis = tuple(truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
        title = "Top API calls for principal '{}' (max. entries: {})".format(principal, PLOT_MAX_ITEMS)
        file_stem = os.path.abspath(os.path.join(principals_dir, str_to_filename(principal)))
        output_file = truncate_str(file_stem, PLOT_MAX_LENGTH_FILE_STEM) + ".png"
        write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate region summary plot
    total_api_calls_per_region = {}
    for region in data["api_calls_by_region"]:
        total_api_calls_per_region[region] = 0
        for api_call in data["api_calls_by_region"][region]:
            total_api_calls_per_region[region] += data["api_calls_by_region"][region][api_call]
    x_axis, y_axis = dict_to_sorted_tuples(total_api_calls_per_region, PLOT_MAX_ITEMS)
    x_axis = tuple(truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
    title = "API calls per region (max. entries: {})".format(PLOT_MAX_ITEMS)
    output_file = os.path.join(plots_dir, "summary_regions.png")
    write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate region detail plots
    for region in data["api_calls_by_region"]:
        region_data = data["api_calls_by_region"][region]
        x_axis, y_axis = dict_to_sorted_tuples(region_data, PLOT_MAX_ITEMS)
        x_axis = tuple(truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
        title = "Top API calls for region '{}' (max. entries: {})".format(region, PLOT_MAX_ITEMS)
        file_stem = os.path.abspath(os.path.join(regions_dir, str_to_filename(region)))
        output_file = truncate_str(file_stem, PLOT_MAX_LENGTH_FILE_STEM) + ".png"
        write_plot_to_file(x_axis, y_axis, title, output_file)


def dict_to_sorted_tuples(val, max_items):
    """
    Returns two tuples that represent the keys and the values of the given dict in descending order of the values.
    Only the largest values are returned in the tuples, until the tuple length reaches the given max_items.
    Example input:
        {"a": 3, "b": 9, "c": 1}
    Example output:
        ("b", "a", "c"), (9, 3, 1)
    """
    val_list = sorted(val.items(), key=lambda val: val[1], reverse=True)[:max_items]
    return zip(*val_list)


def str_to_filename(val):
    """
    Returns a string derived from the given string that has characters replaced that are invalid in many modern file
    systems.
    Example input:
        "arn:aws:iam::123456789012:user/Administrator"
    Example output:
        "arn_aws_iam__123456789012_user_Administrator"
    """
    alphabet = string.ascii_letters + string.digits + "_+=,.@-"
    return "".join(char if char in alphabet else "_" for char in val)


def truncate_str(val, max_length, truncation_sequence="[...]"):
    """
    Returns the given string truncated at the given maximum length. If truncation was applied, the given sequence is
    put as an indication at the end of the string. If the given string does not exceed the maximum length, it is
    returned without changes.
    """
    if len(val) > max_length:
        return val[0 : max_length - len(truncation_sequence)] + truncation_sequence
    return val


def write_plot_to_file(x_axis, y_axis, title, filename):
    """
    Writes a bar chart PNG file with given x_axis, y_axis and title data to the given file name.
    """
    plt.figure(figsize=PLOT_CANVAS_SIZE)
    plt.title(title, wrap=True)
    plt.gca().yaxis.get_major_locator().set_params(integer=True)
    plt.xticks(rotation=90)
    plt.bar(range(len(x_axis)), y_axis, tick_label=x_axis, color="#e4af00")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()


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
        "--threads",
        required=False,
        nargs=1,
        default=[8],
        type=parse_argument_threads,
        help="number of threads to use (one thread analyzes one region), default: 8, minimum: 1, maximum: 32",
    )
    args = parser.parse_args()
    past_hours = args.past_hours[0]
    plot_results = args.plot_results
    profile = args.profile[0] if args.profile else None
    boto_session = boto3.session.Session(profile_name=profile)
    threads = args.threads[0]

    # Test for valid credentials
    sts_client = boto_session.client("sts", config=BOTO_CONFIG, region_name=AWS_DEFAULT_REGION)
    try:
        sts_response = sts_client.get_caller_identity()
        account_id = sts_response["Account"]
        account_principal = sts_response["Arn"]
        print("Analyzing account ID {}".format(account_id))
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        future_to_region_mapping = {}
        for region in enabled_regions:
            future = executor.submit(
                get_cloudtrail_entries_from_region,
                boto_session,
                region,
                from_timestamp,
                run_timestamp,
            )
            futures.append(future)
            future_to_region_mapping[future] = region

        for future in concurrent.futures.as_completed(futures):
            try:
                add_cloudtrail_entries_to_result_collection(future.result(), result_collection)
            except Exception as ex:
                error_message = ex.response["Error"]["Code"]
                region = future_to_region_mapping[future]
                print("Failed reading data from region {}: {}".format(region, error_message))
                result_collection["_metadata"]["regions_failed"][region] = error_message

    # Write result file
    output_file_name = "account_activity_{}_{}.json".format(account_id, run_timestamp_str)
    with open(output_file_name, "w") as out_file:
        json.dump(result_collection, out_file, indent=2, sort_keys=True)
    print("Output file written to {}".format(output_file_name))

    # Write plot files, if configured
    if plot_results:
        print("Generating plots")
        output_dir_name = "account_activity_{}_{}_plots".format(account_id, run_timestamp_str)
        generate_plot_files(result_collection, output_dir_name)
        print("Plot files written to {}".format(output_dir_name))
