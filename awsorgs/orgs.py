#!/usr/bin/env python


"""Manage recources in an AWS Organization.

Usage:
  awsorgs (report|organization|reverse-setup)   [--config FILE]
                                                [--spec-dir PATH]
                                                [--template-dir PATH --output-dir PATH] [--force]
                                                [--master-account-id ID]
                                                [--auth-account-id ID]
                                                [--org-access-role ROLE]
                                                [--exec] [-q] [-d|-dd]


  awsorgs (--help|--version)

Modes of operation:
  report         Display organization status report only.
  orgnanizaion   Run AWS Org management tasks per specification.
  reverse-setup  Generate configuration files from the current AWS Organization deployed
                 - config.yaml, 
                 - spec.d/account.yaml, 
                 - spec.d/common.yaml, 
                 - spec.d/organizational_units.yaml, 
                 - spec.d/service_control_policies.yaml 

Options:
  -h, --help                Show this help message and exit.
  -V, --version             Display version info and exit.
  --config FILE             AWS Org config file in yaml format.
  --spec-dir PATH           Location of AWS Org specification file directory.
  --template-dir PATH       Location of AWS Org specification template files directory containing
                            - config.yaml, 
                            - spec.d/account.yaml, 
                            - spec.d/common.yaml, 
                            - spec.d/organizational_units.yaml, 
                            - spec.d/service_control_policies.yaml 
  --output-dir PATH         Output directory for generated configuration file from an existing AWS Organization
  --force                   Overwrite output directory if exists.
  --master-account-id ID    AWS account Id of the Org master account.    
  --auth-account-id ID      AWS account Id of the authentication account.
  --org-access-role ROLE    IAM role for traversing accounts in the Org.
  --exec                    Execute proposed changes to AWS Org.
  -q, --quiet               Repress log output.
  -d, --debug               Increase log level to 'DEBUG'.
  -dd                       Include botocore and boto3 logs in log stream.
  

"""


import yaml
import json
import time
import shutil


import boto3
from docopt import docopt

import awsorgs
import awsorgs.utils
from awsorgs.utils import *
from awsorgs.spec import *


def validate_accounts_unique_in_org(log, root_spec):
    """
    Make sure accounts are unique across org
    """
    # recursively build mapping of accounts to ou_names
    def map_accounts(spec, account_map={}):
        if 'Accounts' in spec and spec['Accounts']:
            for account in spec['Accounts']:
                if account in account_map:
                    account_map[account].append(spec['Name'])
                else:
                    account_map[account] = [(spec['Name'])]
        if 'Child_OU' in spec and spec['Child_OU']:
            for child_spec in spec['Child_OU']:
                map_accounts(child_spec, account_map)
        return account_map
    # find accounts set to more than one OU
    unique = True
    for account, ou in list(map_accounts(root_spec).items()):
        if len(ou) > 1:
            log.error("Account '%s' set in multiple OU: %s" % (account, ou))
            unique = False
    if not unique:
        log.error("Invalid org_spec: Do not assign accounts to multiple Organizatinal Units")
        sys.exit(1)


def enable_policy_type_in_root(org_client, root_id):
    """
    Ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.list_roots()['Roots'][0]['PolicyTypes']
    if (not p_type or (p_type[0]['Type'] == 'SERVICE_CONTROL_POLICY'
            and p_type[0]['Status'] != 'ENABLED')):
        org_client.enable_policy_type(RootId=root_id, PolicyType='SERVICE_CONTROL_POLICY')


def get_parent_id(org_client, account_id):
    """
    Query deployed AWS organanization for 'account_id. Return the 'Id' of
    the parent OrganizationalUnit or 'None'.
    """
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    try:
        len(parents) == 1
        return parents[0]['Id']
    except:
        raise RuntimeError("API Error: account '%s' has more than one parent: "
                % (account_id, parents))


def list_policies_in_ou (org_client, ou_id):
    """
    Query deployed AWS organanization.  Return a list (of type dict)
    of policies attached to OrganizationalUnit referenced by 'ou_id'.
    """
    policies_in_ou = org_client.list_policies_for_target(
            TargetId=ou_id, Filter='SERVICE_CONTROL_POLICY')['Policies']
    return sorted([ou['Name'] for ou in policies_in_ou])


def scan_deployed_policies(org_client):
    """
    Return list of Service Control Policies deployed in Organization
    """
    return org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']


def scan_deployed_ou(log, org_client, root_id):
    """
    Recursively traverse deployed AWS Organization.  Return list of
    organizational unit dictionaries.  
    """
    def build_deployed_ou_table(org_client, parent_name, parent_id, parent_path, deployed_ou):
        # recusive sub function to build the 'deployed_ou' table
        response = org_client.list_organizational_units_for_parent( ParentId=parent_id)
        child_ou = response['OrganizationalUnits']
        while 'NextToken' in response and response['NextToken']:
            response = org_client.list_organizational_units_for_parent(
                ParentId=parent_id, NextToken=response['NextToken'])
            child_ou += response['OrganizationalUnits']

        response = org_client.list_accounts_for_parent( ParentId=parent_id)
        accounts = response['Accounts']
        while 'NextToken' in response and response['NextToken']:
            response = org_client.list_accounts_for_parent(
                ParentId=parent_id, NextToken=response['NextToken'])
            accounts += response['Accounts']
        log.debug('parent_name: %s; ou: %s' % (parent_name, yamlfmt(child_ou)))
        log.debug('parent_name: %s; accounts: %s' % (parent_name, yamlfmt(accounts)))

        if not deployed_ou:
            deployed_ou.append(dict(
                    Name = parent_name,
                    Id = parent_id,
                    Path = parent_path,
                    Key = parent_id,
                    Child_OU = [ou['Name'] for ou in child_ou if 'Name' in ou],
                    Child_OU_Path = [(parent_path + '/' + ou['Name']) for ou in child_ou if 'Name' in ou],
                    Accounts = [acc['Name'] for acc in accounts if 'Name' in acc]))
        else:
            for ou in deployed_ou:
                if ou['Path'] == parent_path:
                    ou['Child_OU'] = [d['Name'] for d in child_ou]
                    ou['Child_OU_Path'] = [(parent_path + '/' + d['Name']) for d in child_ou]
                    ou['Accounts'] = [d['Name'] for d in accounts]
        for ou in child_ou:
            ou['ParentId'] = parent_id
            ou['Path'] = parent_path + '/' + ou['Name']
            ou['Key'] = parent_id + ':' + ou['Name'] 
            deployed_ou.append(ou)
            build_deployed_ou_table(org_client, ou['Name'], ou['Id'], parent_path + '/' + ou['Name'], deployed_ou)

    # build the table 
    deployed_ou = []
    build_deployed_ou_table(org_client, 'root', root_id, '/root', deployed_ou)
    log.debug('\n' + yamlfmt(deployed_ou))
    return deployed_ou

def reverse_ou(org_client, log, deployed, ou_path, default_sc_policy):
    deployed_ou = lookup(deployed['ou'], 'Path', ou_path)
    revers = []
    ou = dict()
    ou["Name"] = deployed_ou["Name"]
    if "Accounts" in deployed_ou and len(deployed_ou["Accounts"]) > 0: ou["Accounts"] = deployed_ou["Accounts"]
    if "Child_OU_Path" in deployed_ou and len(deployed_ou['Child_OU_Path']) > 0: ou["Child_OU"] = [reverse_ou(org_client, log, deployed, child_OU_Path, default_sc_policy)[0] for child_OU_Path in deployed_ou['Child_OU_Path']] 
    policies = list_policies_in_ou(org_client, deployed_ou["Id"])
    # # ou["SC_Policies"] = policies
    if len(policies) > 1:
        policies.remove(default_sc_policy)
        ou["SC_Policies"] = policies
    revers.append(ou)    
    return revers

def reverse_policies(org_client, log, deployed):
    policies = []
    for policy in deployed['policies']:
        policies.append(dict(
            PolicyName = policy['Name'],
            Description = policy['Description'],
            Statement = json.loads(org_client.describe_policy(PolicyId=policy['Id'])['Policy']['Content'])["Statement"]
        ))
    return policies

def reverse_accounts(org_client, log, deployed, org_access_role):
    aliases = get_account_aliases(log, deployed["accounts"], org_access_role)
    accounts = []
    for account in deployed["accounts"]:
        if account["Status"] == 'ACTIVE':
            item = dict()
            item["Name"] = account["Name"]
            item["Email"] = account["Email"]
            tags = scan_deployed_tags_for_resource(log, org_client, account["Id"])
            if len(tags) > 0: item["Tags"] = tags
            if account["Id"] in aliases and aliases[account["Id"]]: item["Alias"] = aliases[account["Id"]]
            accounts.append(item)
        else:
            log.info("Account %s (%s) is %s, then not added to the configuration" % (account["Name"], account["Id"], account["Status"]))
            pass

    return accounts


def display_provisioned_policies(org_client, log, deployed):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    header = "Provisioned Service Control Policies:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for policy in deployed['policies']:
        log.info("\nName:\t\t%s" % policy['Name'])
        log.info("Description:\t%s" % policy['Description'])
        log.info("Id:\t%s" % policy['Id'])
        log.info("Content:")
        log.info(json.dumps(json.loads(org_client.describe_policy(
                PolicyId=policy['Id'])['Policy']['Content']),
                indent=2,
                separators=(',', ': ')))


def display_provisioned_ou(org_client, log, deployed_ou, parent_path, indent=0):
    """
    Recursive function to display the deployed AWS Organization structure.
    """
    # query aws for child orgs
    ou = lookup(deployed_ou, 'Path', parent_path)
    parent_id = lookup(deployed_ou, 'Path', parent_path, 'Id')
    child_ou_list = lookup(deployed_ou, 'Path', parent_path, 'Child_OU')
    child_accounts = lookup(deployed_ou, 'Path', parent_path, 'Accounts')
    # display parent ou name
    tab = '  '
    log.info(tab*indent + ou['Name'] + ' (' + ou['Path'] + '):')
    # look for policies
    policy_names = list_policies_in_ou(org_client, parent_id)
    if len(policy_names) > 0:
        log.info(tab*indent + tab + 'Policies: ' + ', '.join(policy_names))
    # look for accounts
    account_list = sorted(child_accounts)
    if len(account_list) > 0:
        log.info(tab*indent + tab + 'Accounts: ' + ', '.join(account_list))
    # look for child OUs
    if child_ou_list:
        log.info(tab*indent + tab + 'Child_OU:')
        indent+=2
        for ou_Name in child_ou_list:
            ou_path = parent_path + '/' + ou_Name
            # recurse
            display_provisioned_ou(org_client, log, deployed_ou, ou_path, indent)


def manage_account_moves(org_client, args, log, deployed, ou_spec, dest_parent_id, ou_spec_path):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on OU specification.
    """
    if 'Accounts' in ou_spec and ou_spec['Accounts']:
        for account in ou_spec['Accounts']:
            account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
            if not account_id:
                log.warn("Account '%s' not yet in Organization" % account)
            else:
                source_parent_id = get_parent_id(org_client, account_id)
                if dest_parent_id != source_parent_id:
                    # log.info("Moving account '%s' to OU '%s'" % (account, ou_spec['Name']))
                    log.info("Moving account '%s' to OU '%s'" % (account, ou_spec_path))
                    if args['--exec']:
                        org_client.move_account(
                                AccountId=account_id,
                                SourceParentId=source_parent_id,
                                DestinationParentId=dest_parent_id)


def place_unmanged_accounts(org_client, args, log, deployed, account_list, dest_parent):
    """
    Move any unmanaged accounts into the default OU.
    """
    log.warn("move_unmanaged_account: True - New config to control if unmanaged account move to default OU")
    for account in account_list:
        account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
        dest_parent_id   = lookup(deployed['ou'], 'Name', dest_parent, 'Id')
        source_parent_id = get_parent_id(org_client, account_id)
        if dest_parent_id and dest_parent_id != source_parent_id:
            log.info("Moving unmanged account '%s' to default OU '%s'" %
                    (account, dest_parent))
            if args['--exec']:
                org_client.move_account(
                        AccountId=account_id,
                        SourceParentId=source_parent_id,
                        DestinationParentId=dest_parent_id)


def manage_policies(org_client, args, log, deployed, org_spec):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the sc_policies specification.  Do not touch
    the default policy.  Do not delete an attached policy.
    """
    for p_spec in org_spec['sc_policies']:
        policy_name = p_spec['PolicyName']
        log.debug("considering sc_policy: %s" % policy_name)
        # dont touch default policy
        if policy_name == org_spec['default_sc_policy']:
            continue
        policy = lookup(deployed['policies'], 'Name', policy_name)
        # delete existing sc_policy
        if ensure_absent(p_spec):
            if policy:
                log.info("Deleting policy '%s'" % (policy_name))
                # dont delete attached policy
                if org_client.list_targets_for_policy(PolicyId=policy['Id'])['Targets']:
                    log.error("Cannot delete policy '%s'. Still attached to OU" %
                            policy_name)
                elif args['--exec']:
                    org_client.delete_policy(PolicyId=policy['Id'])
            continue
        # create or update sc_policy
        policy_doc = json.dumps(dict(Version='2012-10-17', Statement=p_spec['Statement']))
        log.debug("spec sc_policy_doc: %s" % yamlfmt(policy_doc))
        # create new policy
        if not policy:
            log.info("Creating policy '%s'" % policy_name)
            if args['--exec']:
                org_client.create_policy(
                        Content=policy_doc,
                        Description=p_spec['Description'],
                        Name=p_spec['PolicyName'],
                        Type='SERVICE_CONTROL_POLICY')
        # check for policy updates
        else:
            deployed_policy_doc = json.dumps(json.loads(org_client.describe_policy(
                    PolicyId=policy['Id'])['Policy']['Content']))
            log.debug("real sc_policy_doc: %s" % yamlfmt(deployed_policy_doc))
            if (p_spec['Description'] != policy['Description']
                or policy_doc != deployed_policy_doc):
                log.info("Updating policy '%s'" % policy_name)
                if args['--exec']:
                    org_client.update_policy(
                            PolicyId=policy['Id'],
                            Content=policy_doc,
                            Description=p_spec['Description'],)


def manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou_id, ou_spec_path):
    """
    Attach or detach specified Service Control Policy to a deployed 
    OrganizatinalUnit.  Do not detach the default policy ever.
    """
    # create lists policies_to_attach and policies_to_detach
    attached_policy_list = list_policies_in_ou(org_client, ou_id)
    if 'SC_Policies' in ou_spec and isinstance(ou_spec['SC_Policies'], list):
        spec_policy_list = ou_spec['SC_Policies']
    else:
        spec_policy_list = []
    policies_to_attach = [p for p in spec_policy_list
            if p not in attached_policy_list]
    policies_to_detach = [p for p in attached_policy_list
            if p not in spec_policy_list
            and p != org_spec['default_sc_policy']]
    # attach policies
    for policy_name in policies_to_attach:
        if not lookup(deployed['policies'],'Name',policy_name):
            if args['--exec']:
                raise RuntimeError("spec-file: ou_spec: policy '%s' not defined" %
                        policy_name)
        if not ensure_absent(ou_spec):
            log.info("Attaching policy '%s' to OU '%s'" % (policy_name, ou_spec_path))
            # log.info("Attaching policy '%s' to OU '%s'" % (policy_name, ou_spec['Name']))
            if args['--exec']:
                org_client.attach_policy(
                        PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                        TargetId=ou_id)
    # detach policies
    for policy_name in policies_to_detach:
        log.info("Detaching policy '%s' from OU '%s'" % (policy_name, ou_spec_path))
        # log.info("Detaching policy '%s' from OU '%s'" % (policy_name, ou_spec['Name']))
        if args['--exec']:
            org_client.detach_policy(
                    PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                    TargetId=ou_id)


def manage_ou(org_client, args, log, deployed, org_spec, ou_spec_list, parent_name, parent_path):
    """
    Recursive function to manage OrganizationalUnits in the AWS
    Organization.
    """
    for ou_spec in ou_spec_list:
        ou_spec_path = parent_path + '/' + ou_spec['Name']
        ou_spec['Path'] = ou_spec_path
        # ou exists
        ou = lookup(deployed['ou'], 'Path', ou_spec_path)
        if ou:
            # check for child_ou. recurse before other tasks.
            if 'Child_OU' in ou_spec:
                manage_ou(
                    org_client, 
                    args, 
                    log, 
                    deployed, 
                    org_spec, 
                    ou_spec['Child_OU'], 
                    ou_spec['Name'], 
                    ou_spec['Path'])
            # check if ou 'absent'
            if ensure_absent(ou_spec):
                log.info("Deleting OU %s" % ou_spec['Path'])
                # error if ou contains anything
                error_flag = False
                for key in ['Accounts', 'SC_Policies', 'Child_OU']:
                    if key in ou and ou[key]:
                        log.error("Can not delete OU '%s'. Deployed '%s' exists." % (ou_spec['Path'], key))
                        error_flag = True
                if error_flag:
                    sys.exit(1)
                    continue
                elif args['--exec']:
                    org_client.delete_organizational_unit(OrganizationalUnitId=ou['Id'])
            # manage account and sc_policy placement in OU
            else:
                manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou['Id'], ou_spec['Path'])
                manage_account_moves(org_client, args, log, deployed, ou_spec, ou['Id'], ou_spec['Path'])
        # create new OU
        elif not ensure_absent(ou_spec):
            log.info("Creating new OU '%s' under parent '%s'" % (ou_spec['Path'], parent_name))
            if args['--exec']:
                new_ou = org_client.create_organizational_unit(
                        ParentId=lookup(deployed['ou'],'Path',parent_path,'Id'),
                        Name=ou_spec['Name'])['OrganizationalUnit']
                # account and sc_policy placement
                manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, new_ou['Id'], ou_spec['Path'])
                manage_account_moves(org_client, args, log, deployed, ou_spec, new_ou['Id'], ou_spec['Path'])                 
                # recurse if child OU
                # need to reload deployed['ou'] to make it work
                root_id = get_root_id(org_client)
                deployed['ou'] = scan_deployed_ou(log, org_client, root_id)

                if ('Child_OU' in ou_spec and isinstance(new_ou, dict) and 'Id' in new_ou):
                    manage_ou(
                            org_client, 
                            args, 
                            log, 
                            deployed, 
                            org_spec,
                            ou_spec['Child_OU'], 
                            new_ou['Name'], 
                            ou_spec['Path'])


def main():
    args = docopt(__doc__, version=awsorgs.__version__)
    core(args)


def core(args):
    log = get_logger(args)
    log.debug(args)
    log.warn("Updated code - Laurent Delhomme AWS June 2020")
    log.warn("File common.yaml -> move_unmanaged_account: True|False - Config to control if unmanaged account move to default OU")
    log.warn("File orgs.py --> Manage OU unique key by path instead of name to allow OU with same name in different path")
    log.warn("File orgs.py --> Manage OU recursive creation (need to reload deployed[""ou""] after new OU created)")
    
    if args['reverse-setup']:
        credentials = get_assume_role_credentials(args['--master-account-id'], args['--org-access-role'])
        if isinstance(credentials, RuntimeError):
            log.error(credentials)
            sys.exit(1)

        if '--template-dir' in args and args['--template-dir']:
            template_dir = args['--template-dir']
            template_dir = os.path.expanduser(template_dir)
            if not os.path.isdir(template_dir):
                log.error("template_dir not found: {}".format(template_dir))
                sys.exit(1)

        else:
            log.error("--template-dir required!")
            sys.exit(1)

        if '--output-dir' in args and args['--output-dir']:
            output_dir = args['--output-dir']
            output_dir = os.path.expanduser(output_dir)
            if os.path.isdir(output_dir):
                if '--force' in args and args['--force']:
                    log.info("With '--force', then delete existing output directory '{}".format(output_dir))
                    if args['--exec']:
                        shutil.rmtree(output_dir)
                else:
                    log.error("Output directory '{}' exists and could be not empty. Refusing to overwrite. Use '--force' to force overwrite".format(output_dir))
                    sys.exit(1)
            
        else:
            log.error("--output-dir required!")
            sys.exit(1)

        org_client = boto3.client('organizations', **credentials)
        root_id = get_root_id(org_client)

        deployed = dict(
            policies = scan_deployed_policies(org_client),
            accounts = scan_deployed_accounts(log, org_client),
            ou = scan_deployed_ou(log, org_client, root_id))

        reverse_config = dict(
            organizational_units = reverse_ou(org_client, log, deployed, "/root", "FullAWSAccess"),
            service_control_policies = reverse_policies(org_client, log, deployed),
            accounts = reverse_accounts(org_client, log, deployed, args['--org-access-role'])
        )

        if args['--exec']:
            shutil.copytree(template_dir, output_dir)

            spec_dir = os.path.join(output_dir, "spec.d")
            config_file = os.path.join(output_dir, "config.yaml")
            config_file_common = os.path.join(spec_dir, "common.yaml")

            f = open(config_file,"rt")
            fc = f.read()
            fc = fc.replace('--spec_dir--', "--/spec.d")
            fc = fc.replace('--org_access_role--', args['--org-access-role'])
            fc = fc.replace('000000000000', args['--master-account-id'])
            f.close()
            f = open(config_file,"wt")
            f.write(fc)
            f.close()

            f = open(config_file_common,"rt")
            fc = f.read()
            fc = fc.replace('000000000000', args['--master-account-id'])
            f.close()
            f = open(config_file_common,"wt")
            f.write(fc)
            f.close()

            for key in reverse_config:
                file_name = key + ".yaml"
                file_path = os.path.join(spec_dir, file_name)
                f=open(file_path, "a+")
                f.write ("\r\n")
                f.write(yamlfmt(reverse_config[key]))
                f.close()

        log.info("reverse_config loaded:")
        log.info("\r\n" + yamlfmt(reverse_config))
        if args['--exec']:
            log.info("awsorgs reverse-setup executed with success. Files delivered in {}".format(output_dir))

        return



    args = load_config(log, args)
    credentials = get_assume_role_credentials(args['--master-account-id'], args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        sys.exit(1)
    org_client = boto3.client('organizations', **credentials)
    root_id = get_root_id(org_client)
    deployed = dict(
        policies = scan_deployed_policies(org_client),
        accounts = scan_deployed_accounts(log, org_client),
        ou = scan_deployed_ou(log, org_client, root_id))
        

    if args['report']:
        header = 'Provisioned Organizational Units in Org:'
        overbar = '_' * len(header)
        log.info("\n%s\n%s" % (overbar, header))
        display_provisioned_ou(org_client, log, deployed['ou'], '/root')
        display_provisioned_policies(org_client, log, deployed)
         

    if args['organization']:
        org_spec = validate_spec(log, args)
        root_spec = lookup(org_spec['organizational_units'], 'Name', 'root')
        root_spec['Path'] = '/root'
        validate_master_id(org_client, org_spec)
        validate_accounts_unique_in_org(log, root_spec)

        managed = dict(
                accounts = search_spec(root_spec, 'Accounts', 'Child_OU'),
                ou = search_spec(root_spec, 'Name', 'Child_OU'),
                policies = [p['PolicyName'] for p in org_spec['sc_policies']])

        # ensure default_sc_policy is considered 'managed'
        if org_spec['default_sc_policy'] not in managed['policies']:
            managed['policies'].append(org_spec['default_sc_policy'])
        enable_policy_type_in_root(org_client, root_id)
        manage_policies(org_client, args, log, deployed, org_spec)

        # rescan deployed policies
        deployed['policies'] = scan_deployed_policies(org_client)
        manage_ou(org_client, args, log, deployed, org_spec, org_spec['organizational_units'], 'root', '')

        # check for unmanaged resources
        for key in list(managed.keys()):
            unmanaged= [a['Name'] for a in deployed[key] if a['Name'] not in managed[key]]
            if unmanaged:
                log.warn("Unmanaged %s in Organization: %s" % (key,', '.join(unmanaged)))
                if key ==  'accounts':
                    # # # Laurent Delhomme AWS - June 2020
                    if org_spec['move_unmanaged_account']:
                        # append unmanaged accounts to default_ou
                        place_unmanged_accounts(org_client, args, log, deployed,
                                unmanaged, org_spec['default_ou'])
                    else:
                        log.warn("Updated code, move_unmanaged_account set to False therefore unmanged account not moved to default OU")

                        



if __name__ == "__main__":
    main()

