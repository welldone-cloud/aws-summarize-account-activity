import matplotlib.pyplot as plt
import os
import string


_PLOT_CANVAS_SIZE = (14, 8)

_PLOT_MAX_ITEMS = 50

_PLOT_MAX_LENGTH_X_AXIS_LABELS = 85


def generate_plot_files(data, output_directory):
    """
    Generates plots that visualize the given CloudTrail data and writes them to the given directory as PNG files.
    """

    # API calls by principal summary
    plot_title = "API calls by principal summary"
    data_to_plot = {
        principal: sum(data["api_calls_by_principal"][principal].values())
        for principal in data["api_calls_by_principal"]
    }
    _write_data_to_plot_file(plot_title, data_to_plot, output_directory, "api_calls_by_principal_summary")

    # API calls by principal
    api_calls_by_principal_dir = os.path.join(output_directory, "api_calls_by_principal")
    os.mkdir(api_calls_by_principal_dir)
    for principal in data["api_calls_by_principal"]:
        plot_title = "API calls by principal '{}'".format(principal)
        data_to_plot = data["api_calls_by_principal"][principal]
        _write_data_to_plot_file(plot_title, data_to_plot, api_calls_by_principal_dir, principal)

    # API calls by region summary
    plot_title = "API calls by region summary"
    data_to_plot = {
        region: sum(data["api_calls_by_region"][region].values()) for region in data["api_calls_by_region"]
    }
    _write_data_to_plot_file(plot_title, data_to_plot, output_directory, "api_calls_by_region_summary")

    # API calls by region
    api_calls_by_region_dir = os.path.join(output_directory, "api_calls_by_region")
    os.mkdir(api_calls_by_region_dir)
    for region in data["api_calls_by_region"]:
        plot_title = "API calls by region '{}'".format(region)
        data_to_plot = data["api_calls_by_region"][region]
        _write_data_to_plot_file(plot_title, data_to_plot, api_calls_by_region_dir, region)

    # IP addresses by principal summary
    plot_title = "IP addresses by principal summary"
    data_to_plot = {
        principal: len(data["ip_addresses_by_principal"][principal]) for principal in data["ip_addresses_by_principal"]
    }
    _write_data_to_plot_file(plot_title, data_to_plot, output_directory, "ip_addresses_by_principal_summary")

    # IP addresses by principal
    ip_addresses_by_principal_dir = os.path.join(output_directory, "ip_addresses_by_principal")
    os.mkdir(ip_addresses_by_principal_dir)
    for principal in data["ip_addresses_by_principal"]:
        plot_title = "IP addresses by principal '{}'".format(principal)
        data_to_plot = data["ip_addresses_by_principal"][principal]
        _write_data_to_plot_file(plot_title, data_to_plot, ip_addresses_by_principal_dir, principal)

    # User agents by principal summary
    plot_title = "User agents by principal summary"
    data_to_plot = {
        principal: len(data["user_agents_by_principal"][principal]) for principal in data["user_agents_by_principal"]
    }
    _write_data_to_plot_file(plot_title, data_to_plot, output_directory, "user_agents_by_principal_summary")

    # User agents by principal
    user_agents_by_principal_dir = os.path.join(output_directory, "user_agents_by_principal")
    os.mkdir(user_agents_by_principal_dir)
    for principal in data["user_agents_by_principal"]:
        plot_title = "User agents by principal '{}'".format(principal)
        data_to_plot = data["user_agents_by_principal"][principal]
        _write_data_to_plot_file(plot_title, data_to_plot, user_agents_by_principal_dir, principal)


def _dict_to_sorted_tuples(val, max_items):
    """
    Returns two tuples that represent the keys and the values of the given dict in descending order of the values.
    On value equality, items are sorted lexicographically by key. The tuples are cut off when their length rechaches
    the given max_items.
    Example input:
        {"a": 3, "d": 9, "b": 9, "c": 1}
    Example output:
        ("b", "d", "a", "c"), (9, 9, 3, 1)
    """
    val_list = sorted(val.items(), key=lambda val: (-val[1], val[0]))[:max_items]
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


def _write_data_to_plot_file(plot_title, dict_to_plot, output_directory, output_file_stem):
    """
    Writes a bar chart PNG file. The given dict keys represent the x axis data, the dict values the y axis. Characters
    of the given output file stem may be replaced to ensure valid file names.
    """
    plot_title = "{} (max. entries: {})".format(plot_title, _PLOT_MAX_ITEMS)
    x_axis, y_axis = _dict_to_sorted_tuples(dict_to_plot, _PLOT_MAX_ITEMS)
    x_axis = tuple(_truncate_str(val, _PLOT_MAX_LENGTH_X_AXIS_LABELS) for val in x_axis)
    output_file = os.path.join(output_directory, _str_to_filename(output_file_stem) + ".png")

    plt.figure(figsize=_PLOT_CANVAS_SIZE)
    plt.title(plot_title, wrap=True)
    plt.gca().yaxis.get_major_locator().set_params(integer=True)
    plt.xticks(rotation=90)
    plt.bar(range(len(x_axis)), y_axis, tick_label=x_axis, color="#e4af00")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
