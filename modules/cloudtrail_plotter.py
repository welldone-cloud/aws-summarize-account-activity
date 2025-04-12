import matplotlib.pyplot as plt
import os
import string


_PLOT_CANVAS_SIZE = (16, 8)

_PLOT_COLOR = "#e4af00"

_PLOT_MAX_ITEMS = 40

_PLOT_MAX_LENGTH_LABELS = 85

_PLOT_TRUNCATION_SEQUENCE = "[...]"


def generate_plot_files(data, output_directory):
    """
    Generates plots that visualize the given CloudTrail data and writes them to the given directory as PNG files.
    """

    # API calls by principal summary
    data_to_plot = {
        principal: sum(data["api_calls_by_principal"][principal].values())
        for principal in data["api_calls_by_principal"]
    }
    _write_plot_file(
        "API calls by principal summary",
        data_to_plot,
        output_directory,
        "api_calls_by_principal_summary",
    )

    # API calls by principal
    api_calls_by_principal_dir = os.path.join(output_directory, "api_calls_by_principal")
    os.mkdir(api_calls_by_principal_dir)
    for principal in data["api_calls_by_principal"]:
        data_to_plot = data["api_calls_by_principal"][principal]
        _write_plot_file(
            "API calls by principal '{}'".format(_truncate_str(principal, _PLOT_MAX_LENGTH_LABELS)),
            data_to_plot,
            api_calls_by_principal_dir,
            principal,
        )

    # API calls by region summary
    data_to_plot = {
        region: sum(data["api_calls_by_region"][region].values()) for region in data["api_calls_by_region"]
    }
    _write_plot_file(
        "API calls by region summary",
        data_to_plot,
        output_directory,
        "api_calls_by_region_summary",
    )

    # API calls by region
    api_calls_by_region_dir = os.path.join(output_directory, "api_calls_by_region")
    os.mkdir(api_calls_by_region_dir)
    for region in data["api_calls_by_region"]:
        data_to_plot = data["api_calls_by_region"][region]
        _write_plot_file(
            "API calls by region '{}'".format(_truncate_str(region, _PLOT_MAX_LENGTH_LABELS)),
            data_to_plot,
            api_calls_by_region_dir,
            region,
        )

    # IP addresses by principal summary
    data_to_plot = {
        principal: len(data["ip_addresses_by_principal"][principal]) for principal in data["ip_addresses_by_principal"]
    }
    _write_plot_file(
        "IP addresses by principal summary",
        data_to_plot,
        output_directory,
        "ip_addresses_by_principal_summary",
    )

    # IP addresses by principal
    ip_addresses_by_principal_dir = os.path.join(output_directory, "ip_addresses_by_principal")
    os.mkdir(ip_addresses_by_principal_dir)
    for principal in data["ip_addresses_by_principal"]:
        data_to_plot = data["ip_addresses_by_principal"][principal]
        _write_plot_file(
            "IP addresses by principal '{}'".format(_truncate_str(principal, _PLOT_MAX_LENGTH_LABELS)),
            data_to_plot,
            ip_addresses_by_principal_dir,
            principal,
        )

    # User agents by principal summary
    data_to_plot = {
        principal: len(data["user_agents_by_principal"][principal]) for principal in data["user_agents_by_principal"]
    }
    _write_plot_file(
        "User agents by principal summary",
        data_to_plot,
        output_directory,
        "user_agents_by_principal_summary",
    )

    # User agents by principal
    user_agents_by_principal_dir = os.path.join(output_directory, "user_agents_by_principal")
    os.mkdir(user_agents_by_principal_dir)
    for principal in data["user_agents_by_principal"]:
        data_to_plot = data["user_agents_by_principal"][principal]
        _write_plot_file(
            "User agents by principal '{}'".format(_truncate_str(principal, _PLOT_MAX_LENGTH_LABELS)),
            data_to_plot,
            user_agents_by_principal_dir,
            principal,
        )

    # Error codes by principal summary
    data_to_plot = {
        principal: len(data["error_codes_by_principal"][principal]) for principal in data["error_codes_by_principal"]
    }
    _write_plot_file(
        "Error codes by principal summary",
        data_to_plot,
        output_directory,
        "error_codes_by_principal_summary",
    )

    # Error codes by principal
    error_codes_by_principal_dir = os.path.join(output_directory, "error_codes_by_principal")
    os.mkdir(error_codes_by_principal_dir)
    for principal in data["error_codes_by_principal"]:
        data_to_plot = data["error_codes_by_principal"][principal]
        _write_plot_file(
            "Error codes by principal '{}'".format(_truncate_str(principal, _PLOT_MAX_LENGTH_LABELS)),
            data_to_plot,
            error_codes_by_principal_dir,
            principal,
        )


def _dict_to_sorted_tuples(val):
    """
    Returns two tuples that represent the keys and the values of the given dict in descending order of the values.
    On value equality, items are sorted lexicographically by key.
    Example input:
        {"a": 3, "d": 9, "b": 9, "c": 1}
    Example output:
        ("b", "d", "a", "c"), (9, 9, 3, 1)
    """
    val_list = sorted(val.items(), key=lambda val: (-val[1], val[0]))
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


def _truncate_str(val, max_length):
    """
    Returns the given string truncated at the given maximum length. If truncation was applied, a truncation sequence
    is put as an indication at the end of the string. If the given string does not exceed the maximum length, it is
    returned without changes.
    """
    if len(val) > max_length:
        return val[0 : max_length - len(_PLOT_TRUNCATION_SEQUENCE)] + _PLOT_TRUNCATION_SEQUENCE
    return val


def _write_plot_file(plot_title, dict_to_plot, output_directory, output_file_name):
    """
    Writes a bar chart PNG file. The given dict keys represent the x axis data, the dict values the y axis. Characters
    of the given output file name may be replaced to ensure valid file names.
    """
    try:
        y_axis_labels, x_axis_bar_sizes = _dict_to_sorted_tuples(dict_to_plot)
    except ValueError:
        # There is no data to plot
        return

    # Truncate data and labels, if necessary
    if len(y_axis_labels) > _PLOT_MAX_ITEMS:
        y_axis_labels = y_axis_labels[:_PLOT_MAX_ITEMS] + (_PLOT_TRUNCATION_SEQUENCE,)
        x_axis_bar_sizes = x_axis_bar_sizes[:_PLOT_MAX_ITEMS] + (0,)
    y_axis_labels = tuple(_truncate_str(val, _PLOT_MAX_LENGTH_LABELS) for val in y_axis_labels)

    plt.figure(figsize=_PLOT_CANVAS_SIZE)
    plt.title(plot_title, wrap=True, loc="left")
    plt.barh(y=y_axis_labels, width=x_axis_bar_sizes, color=_PLOT_COLOR)
    plt.gca().yaxis.set_inverted(True)
    plt.gca().xaxis.get_major_locator().set_params(integer=True)
    plt.tight_layout()

    output_file = os.path.join(output_directory, _str_to_filename(output_file_name) + ".png")
    plt.savefig(output_file)
    plt.close()
