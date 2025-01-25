def _get_principal_for_user_identity_type_none(user_identity):
    """
    Examples:
        "userIdentity": {
            "accountId": "112233445566"
        }

        "userIdentity": {
            "accountId": "112233445566",
            "invokedBy": "ec2.amazonaws.com"
        }

        "userIdentity": {
            "accountId": "112233445566",
            "invokedBy": "AWS Internal"
        }
    """
    try:
        return user_identity["invokedBy"]
    except KeyError:
        return user_identity["accountId"]


def _get_principal_for_user_identity_type_iamuser(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAXIDPCKD31IR6W1TAD",
            "arn": "arn:aws:iam::112233445566:user/testuser",
            "accountId": "112233445566",
            "accessKeyId": "AKIAXIDPCD3KEXAMPLE",
            "userName": "testuser"
        }

        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAQD7C323UJRJN7AQDK",
            "arn": "arn:aws:iam::112233445566:user/username",
            "accountId": "112233445566",
            "accessKeyId": "ASIAQD7C323UAEXAMPLE",
            "userName": "username",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2022-05-20T14:41:59Z",
                    "mfaAuthenticated": "false"
                }
            }
        }

        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAQD7C323UJRJN7AQDK",
            "arn": "arn:aws:iam::112233445566:user/testuser",
            "accountId": "112233445566",
            "accessKeyId": "AIDAQD7C323UJRJN7AQDK",
            "userName": "testuser",
            "sessionContext": {
                "attributes": {
                    "creationDate": "2024-12-20T09:57:36Z",
                    "mfaAuthenticated": "false"
                }
            },
            "invokedBy": "secretsmanager.amazonaws.com"
        }

        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAQE9C5D3UNHG5CG6MV",
            "accountId": "112233445566",
            "accessKeyId": "",
            "userName": "username"
        }
    """
    return "{}:user/{}".format(user_identity["accountId"], user_identity["userName"])


def _get_principal_for_user_identity_type_assumedrole(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROADK7C2S3AD43XKJY6V:sessionname",
            "arn": "arn:aws:sts::112233445566:assumed-role/OrganizationAccountAccessRole/sessionname",
            "accountId": "112233445566",
            "accessKeyId": "ASIAQK7C5S3UNEXAMPLE",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROADK7C2S3AD43XKJY6V",
                    "arn": "arn:aws:iam::112233445566:role/OrganizationAccountAccessRole",
                    "accountId": "112233445566",
                    "userName": "OrganizationAccountAccessRole"
                },
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-04-20T11:49:51Z",
                    "mfaAuthenticated": "false"
                }
            }
        }

        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAQKCD5S2UD43XKJY6V:Administrator",
            "arn": "arn:aws:sts::112233445566:assumed-role/OrganizationAccountAccessRole/Administrator",
            "accountId": "112233445566"
        }

        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROA2DRSAPBKO6NKMASFM:user@example.com",
            "arn": "arn:aws:iam::112233445566:role/aws-reserved/sso.amazonaws.com/eu-central-1/AWSReservedSSO_AdministratorAccess_ccf1d4a38ab69010",
            "accountId": "112233445566",
            "accessKeyId": "ASIA2XDS1PBSLEXAMPLE"
        }

        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "112233445566:aws:ec2-instance:i-0784406a8a14355fe",
            "arn": "arn:aws:sts::112233445566:assumed-role/aws:ec2-instance/i-0784406a8a14355fe",
            "accountId": "112233445566",
            "accessKeyId": "ASIA2KRS2PBAFEXAMPLE",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "112233445566:aws:ec2-instance",
                    "arn": "arn:aws:iam::112233445566:role/aws:ec2-instance",
                    "accountId": "112233445566",
                    "userName": "aws:ec2-instance"
                },
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-12-17T16:41:42Z",
                    "mfaAuthenticated": "false"
                },
                "ec2RoleDelivery": "2.0"
            }
        }

        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROA2XRS6PCBSRQW742QV:TestFunction",
            "arn": "arn:aws:sts::112233445566:assumed-role/LambdaBasicExecutionRole/TestFunction",
            "accountId": "112233445566",
            "accessKeyId": "ASIA2XRS6PBSDEXAMPLE",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROA2XRS6PCBSRQW742QV",
                    "arn": "arn:aws:iam::112233445566:role/LambdaBasicExecutionRole",
                    "accountId": "112233445566",
                    "userName": "LambdaBasicExecutionRole"
                },
                "attributes": {
                    "creationDate": "2025-01-24T11:04:57Z",
                    "mfaAuthenticated": "false"
                }
            },
            "inScopeOf": {
                "issuerType": "AWS::Lambda::Function",
                "credentialsIssuedTo": "arn:aws:lambda:eu-central-1:112233445566:function:TestFunction"
            }
        }
    """
    try:
        arn = user_identity["sessionContext"]["sessionIssuer"]["arn"]
    except KeyError:
        arn = user_identity["arn"]
    if ":assumed-role/" in arn:
        return "{}:role/{}".format(user_identity["accountId"], arn.split("/")[-2])
    elif ":role/" in arn:
        return "{}:role/{}".format(user_identity["accountId"], arn.split("/")[-1])
    else:
        raise ValueError(user_identity)


def _get_principal_for_user_identity_type_root(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "Root",
            "principalId": "112233445566",
            "arn": "arn:aws:iam::112233445566:root",
            "accountId": "112233445566",
            "accessKeyId": ""
        }

        "userIdentity": {
            "type": "Root",
            "principalId": "112233445566",
            "arn": "arn:aws:iam::112233445566:root",
            "accountId": "112233445566",
            "accessKeyId": "EXAMPLE4XX3IEV4PFQTH",
            "userName": "account_name",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-09-15T03:51:31Z",
                    "mfaAuthenticated": "false"
                }
            }
        }

        "userIdentity": {
            "type": "Root",
            "principalId": "112233445566",
            "arn": "arn:aws:iam::112233445566:root",
            "accountId": "112233445566",
            "accessKeyId": "ASIAQD7C323UAEXAMPLE",
            "sessionContext": {
                "attributes": {
                    "creationDate": "2024-10-25T20:00:11Z",
                    "mfaAuthenticated": "false"
                }
            }
        }
    """
    return "{}:root".format(user_identity["accountId"])


def _get_principal_for_user_identity_type_awsaccount(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "AWSAccount",
            "principalId": "AIDAQRSTUVWXYZEXAMPLE",
            "accountId": "112233445566"
        }

        "userIdentity": {
            "type": "AWSAccount",
            "principalId": "AIDAQRSTUVWXYZEXAMPLE:f592575d-41d2-4f1c-a1ef-cfd7dbb52aef",
            "accountId": "112233445566",
            "invokedBy": "cloudformation.amazonaws.com"
        }
    """
    try:
        return user_identity["invokedBy"]
    except KeyError:
        return user_identity["accountId"]


def _get_principal_for_user_identity_type_awsservice(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "AWSService",
            "invokedBy": "eks.amazonaws.com"
        }

        "userIdentity": {
            "type": "AWSService",
            "invokedBy": "AWS Internal"
        }
    """
    return user_identity["invokedBy"]


def _get_principal_for_user_identity_type_federateduser(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "FederatedUser",
            "principalId": "EXAMPLEF3F6F6NXQB6KUH:federateduser",
            "arn": "arn:aws:sts::112233445566:federated-user/federateduser",
            "accountId": "112233445566",
            "accessKeyId": "EXAMPLEC5S3UNSYONYYD",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "IAMUser",
                    "principalId": "EXAMPLEF3F6F6NXQB6KUH",
                    "arn": "arn:aws:iam::112233445566:user/iamuser",
                    "accountId": "112233445566",
                    "userName": "iamuser"
                },
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-08-02T19:10:13Z",
                    "mfaAuthenticated": "false"
                }
            }
        }
    """
    if user_identity["sessionContext"]["sessionIssuer"]["type"] == "Root":
        return "{}:root".format(user_identity["accountId"])
    else:
        return "{}:user/{}".format(
            user_identity["accountId"],
            user_identity["sessionContext"]["sessionIssuer"]["arn"].split("/")[-1],
        )


def _get_principal_for_user_identity_type_identitycenteruser(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "IdentityCenterUser",
            "accountId": "112233445566",
            "onBehalfOf": {
                "userId": "544894e8-80c1-101e-60e3-3ba6510dfac1",
                "identityStoreArn": "arn:aws:identitystore::112233445566:identitystore/d-1237642fc7"
            },
            "credentialId": "VHULjJdTUdPJfofVa1sufHDoj7aYcOYcxFVllWR_Whr1fEXAMPLE"
        }
    """
    return "{}:identitycenteruser/{}/{}".format(
        user_identity["accountId"],
        user_identity["onBehalfOf"]["identityStoreArn"].split("/")[-1],
        user_identity["onBehalfOf"]["userId"],
    )


def _get_principal_for_user_identity_type_webidentityuser(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "WebIdentityUser",
            "principalId": "arn:aws:iam::112233445566:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/07BEE85D60FDEXAMPLE:sts.amazonaws.com:system:serviceaccount:kube-system:cluster-autoscaler",
            "userName": "system:serviceaccount:kube-system:cluster-autoscaler",
            "identityProvider": "arn:aws:iam::112233445566:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/07BEE85D60FDEXAMPLE"
        }

        "userIdentity": {
            "type": "WebIdentityUser",
            "principalId": "arn:aws:iam::112233445566:oidc-provider/app.terraform.io:aws.workload.identity:organization:my-organization:project:my-project:workspace:terraform-cloud:run_phase:plan",
            "userName": "organization:my-organization:project:my-project:workspace:terraform-cloud:run_phase:plan",
            "identityProvider": "arn:aws:iam::112233445566:oidc-provider/app.terraform.io"
        }
    """
    user_identifier = user_identity["principalId"].split("/", 1)[1]
    return "oidc:{}".format(user_identifier)


def _get_principal_for_user_identity_type_samluser(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "SAMLUser",
            "principalId": "bdGOnUkh1i4L/jEvs=:testuser",
            "userName": "testuser",
            "identityProvider": "bdGOnUkh1i4L/jEvs="
        }

        "userIdentity": {
            "type": "SAMLUser",
            "principalId": "lUqu3Gchksa6MnzH4DmnCtbi8nA=:user@company.com",
            "userName": "user@company.com",
            "identityProvider": "lUqu3Gchksa6MnzH4DmnCtbi8nA="
        }
    """
    return "saml:{}".format(user_identity["principalId"])


def _get_principal_for_user_identity_type_unknown(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "Unknown",
            "principalId": "Anonymous"
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "",
            "accountId": "112233445566",
            "userName": ""
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "test.domain//S-1-5-21-2119430433-125441244-1367485280-1124",
            "accountId": "",
            "userName": "admin@test.domain"
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "112233445566",
            "arn": "",
            "accountId": "112233445566",
            "accessKeyId": ""
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "AIDACQE7PABE4SCFBIF4Q",
            "arn": "arn:aws:iam::112233445566:user/user@example.com",
            "accountId": "112233445566",
            "accessKeyId": "AKIABBEB1VB23EXAMPLE",
            "userName": "user@example.com"
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "AROAVCD2NAYBRXTC2NSCF:Administrator",
            "arn": "arn:aws:sts::112233445566:assumed-role/OrganizationAccountAccessRole/Administrator",
            "accountId": "112233445566",
            "accessKeyId": "Unknown",
            "userName": "assumed-role/OrganizationAccountAccessRole/Administrator"
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "112233445566",
            "arn": "arn:aws:iam::112233445566:root",
            "accountId": "112233445566",
            "accessKeyId": "Unknown",
            "userName": "WebsiteAccount"
        }

        "userIdentity": {
            "type": "Unknown",
            "principalId": "2324a8e2-8051-7072-11c2-1126a311c4a0",
            "accountId": "112233445566",
            "userName": "user@example.com"
        }

        "userIdentity": {
            "type": "Unknown",
            "userName": "someuser",
            "accountId": "112233445566",
            "principalId": "112233445566",
            "onBehalfOf": {
                "userId": "111111-1111-1111-1111-111111111111",
                "identityStoreArn": "arn:aws:identitystore::111111111:identitystore/d-111111111"
            }
        }
    """
    try:
        arn = user_identity["arn"]
        if not arn:
            raise KeyError()
        if arn.endswith(":root"):
            return "{}:root".format(user_identity["accountId"])
        elif ":user/" in arn or ":federated-user/" in arn:
            return "{}:user/{}".format(user_identity["accountId"], arn.split("/")[-1])
        elif ":assumed-role/" in arn:
            return "{}:role/{}".format(user_identity["accountId"], arn.split("/")[-2])
        elif ":role/" in arn:
            return "{}:role/{}".format(user_identity["accountId"], arn.split("/")[-1])
        else:
            raise KeyError()
    except KeyError:
        try:
            return "{}:identitycenteruser/{}/{}".format(
                user_identity["accountId"],
                user_identity["onBehalfOf"]["identityStoreArn"].split("/")[-1],
                user_identity["onBehalfOf"]["userId"],
            )
        except KeyError:
            pass
        try:
            account_id = user_identity["accountId"]
            if not account_id:
                raise KeyError()
            return account_id
        except KeyError:
            return user_identity["type"]


def _get_principal_for_user_identity_type_directory(user_identity):
    """
    Examples:
        "userIdentity": {
            "type": "Directory",
            "arn": "arn:aws:ds:us-east-1:112233445566:user/d-0000cafe00/00000000-0000-0000-0000-000000000000",
            "accountId": "112233445566",
            "userName": "user@example.com"
        }
    """
    split_arn = user_identity["arn"].split("/")
    return "{}:ds/{}/{}".format(
        user_identity["accountId"],
        split_arn[-2],
        split_arn[-1],
    )


def get_principal_from_log_record(log_record):
    """
    Returns the principal that is contained in the "userIdentity" field of the given log record.
    """
    user_identity = log_record["userIdentity"]
    try:
        user_identity_type = user_identity["type"]
    except KeyError:
        user_identity_type = "None"

    principal_extraction_functions = {
        "None": _get_principal_for_user_identity_type_none,
        "IAMUser": _get_principal_for_user_identity_type_iamuser,
        "AssumedRole": _get_principal_for_user_identity_type_assumedrole,
        "Root": _get_principal_for_user_identity_type_root,
        "AWSAccount": _get_principal_for_user_identity_type_awsaccount,
        "AWSService": _get_principal_for_user_identity_type_awsservice,
        "FederatedUser": _get_principal_for_user_identity_type_federateduser,
        "IdentityCenterUser": _get_principal_for_user_identity_type_identitycenteruser,
        "WebIdentityUser": _get_principal_for_user_identity_type_webidentityuser,
        "SAMLUser": _get_principal_for_user_identity_type_samluser,
        "Unknown": _get_principal_for_user_identity_type_unknown,
        "Directory": _get_principal_for_user_identity_type_directory,
    }
    try:
        return principal_extraction_functions[user_identity_type](user_identity)
    except KeyError:
        raise ValueError("Unrecognized userIdentity format", log_record)


def get_api_call_from_log_record(log_record):
    """
    Returns the API service and action name that is invoked in the given log record.
    """
    return "{}:{}".format(log_record["eventSource"], log_record["eventName"])


def get_error_code_from_log_record(log_record):
    """
    Returns the error code contained in the given log record or None if there is no error code.
    """
    try:
        return "{}:{}".format(log_record["eventSource"], log_record["errorCode"])
    except KeyError:
        pass
    try:
        return "{}:{}".format(log_record["eventSource"], log_record["responseElements"]["errorCode"])
    except (KeyError, TypeError):
        return None


def get_ip_address_from_log_record(log_record):
    """
    Returns the source IP address contained in the given log record. Note that the value returned may
    not be an actual IP address, but an AWS service name or "AWS Internal".
    """
    try:
        return log_record["sourceIPAddress"]
    except KeyError:
        return "Unknown"


def get_user_agent_from_log_record(log_record):
    """
    Returns the user agent string contained in the given log record.
    """
    try:
        return log_record["userAgent"]
    except KeyError:
        return "Unknown"


def is_successful_api_call(log_record):
    """
    Returns True if the given log record describes a successful API call. Returns False if the log
    record contains "errorCode" or "errorMessage" elements.
    """
    if "errorCode" in log_record or "errorMessage" in log_record:
        return False
    if "responseElements" in log_record and log_record["responseElements"]:
        if "errorCode" in log_record["responseElements"] or "errorMessage" in log_record["responseElements"]:
            return False
    return True
