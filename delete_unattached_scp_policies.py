####
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
####
__author__ = 'dc'

import boto3
import sys
import argparse
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import repeat

# #############################
# List all policies
# #############################
def list_all_policies(org_client):
    """
    Find all policies
    :param org_client:
    :return: list(scps)
    """
    try:
        print("Executing method List_all_Policies...")
        list_policies = []
        response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
        list_policies.extend(response['Policies'])
        while 'NextToken' in response:
            response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY', MaxResults=20,
                                                NextToken=response['NextToken'])
            list_policies.extend(response['Policies'])
        # filter out aws-guardrails-*
        list_scps = list(filter(lambda dic: dic['Name'].find("aws-guardrails") < 0, list_policies))
        print(f"Number of policies: {len(list_scps)}")
        return list_scps
    except Exception as err:
        print(err)


###############################
# List targets of all policies
###############################
def list_all_target_policies(org_client, each_policy):
    """
    List targets to find unattached policies
    :param org_client:
    :param list_of_policies:
    :return: list(policyId)
    """
    try:
        # unattached_policies = []
        # for each_policy in list_of_policies:
        print(f'Executing method list_all_target_policies..')
        response = org_client.list_targets_for_policy(PolicyId=each_policy['Id'])
        if not response['Targets']:
            return each_policy['Id']
            # unattached_policies.append(each_policy['Id'])
        # return unattached_policies
    except Exception as err:
        print(err)


###############################
# List targets of all policies
###############################
def delete_policies(org_client, unattached_policies):
    """
    Delete unattached policies
    :param org_client:
    :param unattached_policies:
    :return:
    """
    try:
        for each_policy in unattached_policies:
            response = org_client.delete_policy(PolicyId=each_policy)
            print(response)
    except ClientError as error:
        if error.response['Error']['Code'] == 'PolicyInUseException':
            print(f"PolicyId: {each_policy} is attached to a target")

# #############################
# Main Function
# #############################
def main():
    parser =argparse.ArgumentParser()
    parser.add_argument('-p', '--profile', help="AWS profile name is required")
    args = parser.parse_args()
    if len(sys.argv) == 2:
        parser.print_help()
        sys.exit(0)
    if args.profile:
        session = boto3.session.Session(
            profile_name=args.profile
        )
    else:
        session = boto3.session.Session(
            profile_name=None
        )
    session = session.client('organizations')
    return session


if __name__ == '__main__':
    org_client = main()
    list_of_policies = list_all_policies(org_client)
    with ThreadPoolExecutor(max_workers=2) as executor:
        unattached_policies = [executor.submit(list_all_target_policies, org_client, policy) for policy in list_of_policies]
    for policy in as_completed(unattached_policies):
        print(policy.result())
    for result in unattached_policies:
        print(result)
    print(list_of_policies.result(), unattached_policies.result())
    list_of_policies = list_all_policies(org_client)
    with ThreadPoolExecutor() as executor:
        unattached_policies = executor.submit(list_all_target_policies, org_client, list_of_policies.result())
    unattached_policies = list_all_target_policies(org_client, list_of_policies.result())
    if unattached_policies:
        delete_policies(org_client, unattached_policies)
