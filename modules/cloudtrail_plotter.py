import matplotlib.pyplot as plt
import os
import string


PLOT_CANVAS_SIZE = (14, 8)

PLOT_MAX_ITEMS = 50

PLOT_MAX_LENGTH_FILE_STEM = 250

PLOT_MAX_LENGTH_X_AXIS_LABELS = 85


def generate_plot_files(data, output_directory):
    """
    Generates plots that represent the given CloudTrail data and writes them to the given directory as PNG files.
    """
    os.mkdir(output_directory)
    principals_dir = os.path.join(output_directory, "principals")
    os.mkdir(principals_dir)
    regions_dir = os.path.join(output_directory, "regions")
    os.mkdir(regions_dir)

    # Generate principal summary plot
    total_api_calls_per_principal = {}
    for principal in data["api_calls_by_principal"]:
        total_api_calls_per_principal[principal] = 0
        for api_call in data["api_calls_by_principal"][principal]:
            total_api_calls_per_principal[principal] += data["api_calls_by_principal"][principal][api_call]
    x_axis, y_axis = _dict_to_sorted_tuples(total_api_calls_per_principal, PLOT_MAX_ITEMS)
    x_axis = tuple(_truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
    title = "API calls per principal (max. entries: {})".format(PLOT_MAX_ITEMS)
    output_file = os.path.join(output_directory, "summary_principals.png")
    _write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate principal detail plots
    for principal in data["api_calls_by_principal"]:
        principal_data = data["api_calls_by_principal"][principal]
        x_axis, y_axis = _dict_to_sorted_tuples(principal_data, PLOT_MAX_ITEMS)
        x_axis = tuple(_truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
        title = "Top API calls for principal '{}' (max. entries: {})".format(principal, PLOT_MAX_ITEMS)
        file_stem = os.path.abspath(os.path.join(principals_dir, _str_to_filename(principal)))
        output_file = _truncate_str(file_stem, PLOT_MAX_LENGTH_FILE_STEM) + ".png"
        _write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate region summary plot
    total_api_calls_per_region = {}
    for region in data["api_calls_by_region"]:
        total_api_calls_per_region[region] = 0
        for api_call in data["api_calls_by_region"][region]:
            total_api_calls_per_region[region] += data["api_calls_by_region"][region][api_call]
    x_axis, y_axis = _dict_to_sorted_tuples(total_api_calls_per_region, PLOT_MAX_ITEMS)
    x_axis = tuple(_truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
    title = "API calls per region (max. entries: {})".format(PLOT_MAX_ITEMS)
    output_file = os.path.join(output_directory, "summary_regions.png")
    _write_plot_to_file(x_axis, y_axis, title, output_file)

    # Generate region detail plots
    for region in data["api_calls_by_region"]:
        region_data = data["api_calls_by_region"][region]
        x_axis, y_axis = _dict_to_sorted_tuples(region_data, PLOT_MAX_ITEMS)
        x_axis = tuple(_truncate_str(val, PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
        title = "Top API calls for region '{}' (max. entries: {})".format(region, PLOT_MAX_ITEMS)
        file_stem = os.path.abspath(os.path.join(regions_dir, _str_to_filename(region)))
        output_file = _truncate_str(file_stem, PLOT_MAX_LENGTH_FILE_STEM) + ".png"
        _write_plot_to_file(x_axis, y_axis, title, output_file)


def _dict_to_sorted_tuples(val, max_items):
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


def _str_to_filename(val):
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


def _truncate_str(val, max_length, truncation_sequence="[...]"):
    """
    Returns the given string truncated at the given maximum length. If truncation was applied, the given truncation
    sequence is put as an indication at the end of the string. If the given string does not exceed the maximum length,
    it is returned without changes.
    """
    if len(val) > max_length:
        return val[0 : max_length - len(truncation_sequence)] + truncation_sequence
    return val


def _write_plot_to_file(x_axis, y_axis, title, file_name):
    """
    Writes a bar chart PNG file with given x_axis, y_axis and title data to the given file name.
    """
    plt.figure(figsize=PLOT_CANVAS_SIZE)
    plt.title(title, wrap=True)
    plt.gca().yaxis.get_major_locator().set_params(integer=True)
    plt.xticks(rotation=90)
    plt.bar(range(len(x_axis)), y_axis, tick_label=x_axis, color="#e4af00")
    plt.tight_layout()
    plt.savefig(file_name)
    plt.close()
