# aws-summarize-account-activity

Analyzes CloudTrail data of a given AWS account and generates a summary of recently active IAM principals, API calls they made, as well as regions, IP addresses and user agents they used. The summary is written to a JSON output file and can optionally be visualized as PNG files. 


## Usage

Make sure you have AWS credentials configured for your target account. This can either be done using [environment 
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) or by specifying a [named 
profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) in the optional `--profile` 
argument.

Install dependencies:

```bash
pip install -r requirements.txt
```

Example invocation:

```bash
python aws_summarize_account_activity.py
```


## Supported arguments

All arguments are optional:

```
--activity-type {ALL,SUCCESSFUL,FAILED}
    type of CloudTrail data to analyze: all API calls (default), 
    only successful API calls, or only API calls that AWS declined with an error message
--dump-raw-cloudtrail-data
    store a copy of all gathered CloudTrail data in JSONL format
--past-hours HOURS
    hours of CloudTrail data to look back and analyze
    default: 336 (=14 days), minimum: 1, maximum: 2160 (=90 days)
--plot-results
    generate PNG files that visualize the JSON output file
--profile PROFILE
    named AWS profile to use when running the command
```


## Notes

* The script uses the `LookupEvents` API of CloudTrail to gather information on account activity:

  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html

  This approach has the advantage that it does not require any specific configuration to be present in the target account. There is no need for CloudTrail to be enabled or configured in a certain way (e.g., logging to S3 or CloudWatch). Instead, the script analyzes the CloudTrail event history that is available by default and covers the past 90 days.
  
  The approach comes with the drawback, though, that the `LookupEvents` API is throttled to two requests per second. The script will thus need proportionally more time for AWS accounts with lots of AWS API call activity. If the script takes too long for your use case, consider reducing the timeframe of data analyzed via the `--past-hours` argument. Alternatively, if you are in the position to make changes to the AWS account, analyze large amounts of CloudTrail data using AWS Athena or CloudTrail Lake:

  https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html
  
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html

* The script analyzes management events that were logged to CloudTrail. Please note that there are AWS APIs that do not log to CloudTrail: logging support varies from service to service. 


## Minimum IAM permissions required

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeRegions",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```


## Example output file

Truncated example JSON output file:
```json
{
  "_metadata": {
    "account_id": "123456789012",
    "account_principal": "arn:aws:iam::123456789012:user/myuser",
    "activity_type": "ALL",
    "cloudtrail_data_analyzed": {
      "from_timestamp": "20250103140755",
      "to_timestamp": "20250105140755"
    },
    "invocation": "aws_summarize_account_activity.py --past-hours 48 --plot-results",
    "regions_enabled": [
      "af-south-1",
      "ap-northeast-1",
      "ap-northeast-2",
      "ap-northeast-3",
      "ap-south-1",
      "ap-southeast-1",
      "ap-southeast-2",
      "ca-central-1",
      "eu-central-1",
      "eu-north-1",
      "eu-west-1",
      "eu-west-2",
      "eu-west-3",
      "sa-east-1",
      "us-east-1",
      "us-east-2",
      "us-west-1",
      "us-west-2"
    ],
    "regions_failed": {},
    "run_timestamp": "20250105140755"
  },
  "api_calls_by_principal": {
    "arn:aws:iam::123456789012:user/myuser": {
      "access-analyzer.amazonaws.com:ListPolicyGenerations": 5,
      "access-analyzer.amazonaws.com:ValidatePolicy": 13,
      "ce.amazonaws.com:GetCostAndUsage": 3,
      "ce.amazonaws.com:GetCostForecast": 3,
      "cloudtrail.amazonaws.com:DescribeTrails": 2,
      "cloudtrail.amazonaws.com:GetTrailStatus": 1,
      "cloudtrail.amazonaws.com:ListEventDataStores": 2,
      "cloudtrail.amazonaws.com:LookupEvents": 44,
      "config.amazonaws.com:DescribeConfigurationRecorderStatus": 1,
      "config.amazonaws.com:DescribeConfigurationRecorders": 1,
      "ec2.amazonaws.com:DescribeAccountAttributes": 3,
      "ec2.amazonaws.com:DescribeRegions": 1,
      "health.amazonaws.com:DescribeEventAggregates": 86,
      "iam.amazonaws.com:AttachRolePolicy": 1,
      "iam.amazonaws.com:CreateAccessKey": 1,
      "iam.amazonaws.com:CreateRole": 1,
      "iam.amazonaws.com:CreateUser": 1,
      "iam.amazonaws.com:DeleteAccessKey": 1,
      "iam.amazonaws.com:DeleteRole": 3,
      "signin.amazonaws.com:ConsoleLogin": 6,
      "sso.amazonaws.com:DescribeRegisteredRegions": 1,
      "sts.amazonaws.com:GetCallerIdentity": 1
    },
    "arn:aws:sts::123456789012:role/EC2_role": {
      "s3.amazonaws.com:ListBuckets": 2,
      "ssm.amazonaws.com:ListInstanceAssociations": 8,
      "ssm.amazonaws.com:UpdateInstanceInformation": 14
    },
    "elasticfilesystem.amazonaws.com": {
      "kms.amazonaws.com:Decrypt": 8,
      "sts.amazonaws.com:AssumeRole": 9
    },
    // ...
  },
  "api_calls_by_region": {
    "ap-northeast-1": {
      "cloudtrail.amazonaws.com:GetServiceLinkedChannel": 28,
      "cloudtrail.amazonaws.com:LookupEvents": 7,
      "dynamodb.amazonaws.com:ListTables": 3,
      "ec2.amazonaws.com:DescribeAddresses": 3,
      "ec2.amazonaws.com:DescribeCapacityReservationFleets": 3,
      "ec2.amazonaws.com:DescribeCapacityReservations": 3,
      "ec2.amazonaws.com:DescribeClientVpnEndpoints": 3,
      "ec2.amazonaws.com:DescribeCustomerGateways": 3,
      "ec2.amazonaws.com:DescribeDhcpOptions": 3,
      "ec2.amazonaws.com:DescribeEgressOnlyInternetGateways": 3
    },
    "us-east-1": {
      "access-analyzer.amazonaws.com:ListPolicyGenerations": 5,
      "access-analyzer.amazonaws.com:ValidatePolicy": 13,
      "ce.amazonaws.com:DescribeReport": 2,
      "ce.amazonaws.com:GetCostAndUsage": 17,
      "ce.amazonaws.com:GetCostForecast": 8,
      "ce.amazonaws.com:GetDimensionValues": 5,
      "ce.amazonaws.com:GetReservationPurchaseRecommendation": 1,
      "ce.amazonaws.com:GetReservationUtilization": 2,
      "cloudfront.amazonaws.com:ListCachePolicies": 47,
      "cloudfront.amazonaws.com:ListCloudFrontOriginAccessIdentities": 46
    },
    // ...
  },
  "error_codes_by_principal": {
    "123456789012:user/alice": {
      "cloudcontrolapi.amazonaws.com:ThrottlingException": 71,
      "ram.amazonaws.com:InvalidParameterException": 5,
      "ram.amazonaws.com:ResourceArnNotFoundException": 4,
      "s3.amazonaws.com:AccessDenied": 9
    },
    // ...
  },
  "ip_addresses_by_principal": {
    "123456789012:user/alice": {
      "188.22.117.122": 2383,
      "2001:871:22d:1d63:41d7:81f:7b81:5396": 36,
      "AWS Internal": 8
    },
    "123456789012:role/EC2_role": {
      "52.90.81.4": 285
    },
    // ...
  },
  "user_agents_by_principal": {
    "123456789012:user/bob": {
      "APN/1.0 HashiCorp/1.0 Terraform/1.7.5 (+https://www.terraform.io) terraform-provider-aws/5.44.0 [...]": 61,
      "Boto3/1.34.68 md/Botocore#1.34.68 ua/2.0 os/windows#10 md/arch#amd64 [...]": 36,
      "aws-cli/2.15.31 Python/3.11.8 Windows/10 exe/AMD64 prompt/off [...]": 2
    },
    // ...
  }
}
```


## Example visualizations

When using the optional `--plot-results` argument, visualizations of the JSON output file are generated as PNG files: 

![](./doc/example_plots/api_calls_by_region_1.png)

![](./doc/example_plots/api_calls_by_region_2.png)

![](./doc/example_plots/api_calls_by_principal_1.png)

![](./doc/example_plots/api_calls_by_principal_2.png)

![](./doc/example_plots/ip_addresses_by_principal_1.png)

![](./doc/example_plots/user_agents_by_principal_1.png)


## Generating visualizations retroactively
If you have an existing JSON output file from a previous run and want to generate PNG visualizations for it, you can do so via:

```bash
python generate_plots_for_existing_json_file.py --file account_activity_123456789012_20250105140755.json
```

