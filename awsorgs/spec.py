import sys
import os
import yaml

import boto3
from botocore.exceptions import ClientError
from cerberus import Validator, schema_registry
from pkg_resources import parse_version

import awsorgs
from awsorgs.utils import *
from awsorgs.validator import file_validator, spec_validator

# Spec parser defaults
DEFAULT_CONFIG_FILE = '~/.awsorgs/config.yaml'
DEFAULT_SPEC_DIR = '~/.awsorgs/spec.d'



def scan_config_file(log, args):
    if args['--config']:
        config_file = args['--config']
    else:
        config_file = DEFAULT_CONFIG_FILE
    config_file = os.path.expanduser(config_file)
    # # # log.debug("current directory: {}".format(os.getcwd()))
    if not os.path.isfile(config_file):
        log.error("config_file not found: {}".format(config_file))
        return None
    log.debug("loading config file: {}".format(config_file))
    with open(config_file) as f:
        try:
            config = yaml.safe_load(f.read())
        except (yaml.scanner.ScannerError, UnicodeDecodeError):
            log.error("{} not a valid yaml file".format(config_file))
            return None
        except Exception as e:
            log.error("cant load config_file '{}': {}".format(config_file, e))
            return None
    log.debug("config: {}".format(config))
    return config


def get_master_account_id(log, args, config):
    """
    Determine the Org Master account id.  Try in order:
    cli option, config file, client.describe_organization()
    """
    if '--master-account-id' in args and args['--master-account-id']:
        master_account_id = args['--master-account-id']
    else:
        master_account_id = config.get('master_account_id')
    if master_account_id:
        if not valid_account_id(log, master_account_id):
            log.critical("config option 'master_account_id' is not valid account Id")
            sys.exit(1)
    else:
        log.debug("'master_account_id' not set in config_file or as cli option")
        try:
            master_account_id = boto3.client('organizations'
                    ).describe_organization()['Organization']['MasterAccountId']
        except ClientError as e:
            log.critical("can not determine master_account_id: {}".format(e))
            sys.exit(1)
    log.debug("master_account_id: %s" % master_account_id)
    return master_account_id


def get_spec_dir(log, args, config):
    """
    Determine the spec directory.  Try in order:
    cli option, config file, DEFAULT_SPEC_DIR.
    """
    if '--spec-dir' in args and args['--spec-dir']:
        spec_dir = args['--spec-dir']
    elif config['spec_dir']:
        spec_dir = config['spec_dir']
        if spec_dir.startswith("--/"):
            config_dir = os.path.split(args['--config'])[0]
            spec_dir = os.path.join(config_dir, spec_dir.replace("--/", ""))
    else:
        spec_dir = DEFAULT_SPEC_DIR
    spec_dir = os.path.expanduser(spec_dir)
    log.debug("spec_dir: %s" % spec_dir)
    return spec_dir


def load_config(log, args):
    """
    Assemble config options from various sources: cli options, config_file 
    params, defaults, etc., and merge them into 'args' dict.
    When we are done we should have found all of the following:

    master_account_id
    org_access_role
    spec_dir (except when handling reports)
    auth_account_id (except when called by awsorgs)
    """
    config = scan_config_file(log, args)
    args['--master-account-id'] = get_master_account_id(log, args, config)
    args['--spec-dir'] = get_spec_dir(log, args, config)
    if not ('--org-access-role' in args and args['--org-access-role']):
        args['--org-access-role'] =  config.get('org_access_role')
    if not ( '--auth-account-id' in args and args['--auth-account-id']):
        args['--auth-account-id'] =  config.get('auth_account_id')
    return args


def validate_spec_file(log, spec_file, validator, errors):
    with open(spec_file) as f:
        try:
            spec_from_file = yaml.safe_load(f.read())
        except (yaml.scanner.ScannerError, UnicodeDecodeError):
            log.warn("{} not a valid yaml file. skipping".format(spec_file))
            return (None, errors)
        except Exception as e:
            log.error("cant load spec_file '{}': {}".format(spec_file, e))
            return (None, errors)
    if validator.validate(spec_from_file):
        return (spec_from_file, errors)
    else:
        log.error("schema validation failed for spec_file: {}".format(spec_file))
        log.debug("validator errors:\n{}".format(yamlfmt(validator.errors)))
        errors += 1
        return (None, errors)


def validate_package_version(log, spec_dir):
    common_file_name = next(
        (file for file in os.listdir(spec_dir) if file.startswith('common')),
        None,
    )
    if common_file_name is None:
        log.critical("cannot locate common spec file in spec_dir '{}'".format(spec_dir))
        sys.exit(1)
    common_spec_file = os.path.join(spec_dir, common_file_name)
    log.debug('common spec file: {}'.format(common_spec_file))
    with open(common_spec_file) as f:
        try:
            common_spec = yaml.safe_load(f.read())
        except Exception as e:
            log.critical("cant load common spec file '{}': {}".format(common_spec_file, e))
            sys.exit(1)
    log.debug('minimum_version: {}'.format(common_spec['minimum_version']))
    if not parse_version(awsorgs.__version__) >= parse_version(common_spec['minimum_version']):
        log.critical('Installed aws-orgs package does not meet minimum version requirement. '
                     'Please update your aws-orgs package to version "{}" or higher.'.format(
            common_spec['minimum_version']
        ))
        sys.exit(1)
    return


def validate_spec(log, args):
    """
    Load all spec files in spec_dir and validate against spec schema
    """

    # validate spec_files
    spec_dir = args['--spec-dir']
    if not os.path.isdir(spec_dir):
        log.error("spec_dir not found or not a directory: {}".format(spec_dir))
        sys.exit(1)
    validate_package_version(log, spec_dir)
    validator = file_validator(log)
    spec_object = {}
    errors = 0
    for dirpath, dirnames, filenames in os.walk(spec_dir, topdown = True):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for f in filenames:
            log.debug("considering file {}".format(f))
            spec_from_file, errors = validate_spec_file(log, os.path.join(dirpath, f), validator, errors)
            if spec_from_file:
                spec_object.update(spec_from_file)
    if errors:
        log.critical("schema validation failed for {} spec files. run in debug mode for details".format(errors))
        sys.exit(1)
    log.debug("spec_object:\n{}".format(yamlfmt(spec_object)))

    # validate aggregated spec_object
    validator = spec_validator(log)
    if not validator.validate(spec_object):
        log.critical("spec_object validation failed:\n{}".format(yamlfmt(validator.errors)))
        sys.exit(1)
    log.debug("spec_object validation succeeded")
    
    # root_spec = lookup(spec_object['organizational_units'], 'Name', 'root')
    
    scan_manage_ou_path(spec_object['organizational_units'], '/')
    OUs = flatten_OUs(spec_object['organizational_units'])
    # ous = search_spec(spec_object['organizational_units'][0], 'Path', 'Child_OU')
    for path in OUs:
        ou = OUs[path]
        if 'IncludeConfigPath' in ou:
            child_args = {}
            child_args['--config'] = ou['IncludeConfigPath']
            child_args = load_config(log, child_args)

            child_spec = validate_spec(log, child_args)
            
            # merge child_spec in spec_object
            # check if included config fit with current config
            error=0
            if child_args['--master-account-id'] != args['--master-account-id']:
                log.critical("included config validation failed for {}. Value shoiuld be the same!".format('--master-account-id'))
                error = error +1
            if child_args['--org-access-role'] != args['--org-access-role']:
                log.critical("included config validation failed for {}. Value shoiuld be the same!".format('--org-access-role'))
                error = error +1
            if child_args['--auth-account-id'] != args['--auth-account-id']:
                log.critical("included config validation failed for {}. Value shoiuld be the same!".format('--auth-account-id'))
                error = error +1

            
            # check if monted point fit with included location
            if len(child_spec['organizational_units']) != 1:
                log.critical("included config validation failed. The included org tree should start with one single OU, corresponding to the Parent OU mounting point")
                error = error +1
            if child_spec['organizational_units'][0]['Name'] != ou['Name']:
                log.critical("included config validation failed. The included org tree should start with one single OU with the same Name as the corresponding Parent OU mounting point")
                error = error +1
            if child_spec['organizational_units'][0]['MountingOUPath'] != ou['Path']:
                log.critical("included config validation failed. The included org Mounting pont should the corresponding Parent OU path")
                error = error +1
            if 'Child_OU' in ou:
                log.critical("Mounting point OU should not have child OU already defined")
                error = error +1
            if not 'Child_OU' in child_spec['organizational_units'][0]:
                log.critical("The OU tree to include in not present in the configuration to include")
                error = error +1

            # check if no duplicate for accounts
            if 'accounts' in child_spec and child_spec['accounts'] and 'accounts' in spec_object and spec_object['accounts']:
                for account in child_spec['accounts']:
                    if lookup(spec_object['accounts'], 'Name', account['Name']):
                        log.critical(("Duplicate account ({}) found when merging included config {}.").format(account['Name'], ou['IncludeConfigPath']))
                        error = error +1

            # check if no ducplicate for SCPs
            if 'sc_policies' in child_spec and child_spec['sc_policies'] and 'sc_policies' in spec_object and spec_object['sc_policies']:
                for scp in child_spec['sc_policies']:
                    if lookup(spec_object['sc_policies'], 'PolicyName', scp['PolicyName']):
                        log.critical(("Duplicate SCP ({}) found when merging included config {}.").format(scp['PolicyName'], ou['IncludeConfigPath']))
                        error = error +1
                    if 'PrefixRequired' in ou and ou['PrefixRequired'] and not (scp['PolicyName'].startswith(ou['PrefixRequired'] + '.')):
                        log.critical(("SCP ({}) doesn't match the namming convention defined with prefix {}.").format(scp['PolicyName'], ou['PrefixRequired']))
                        error = error +1

            if error:
                log.critical("schema validation failed. Run in debug mode for details")
                sys.exit(1)
            # check if referenced accounts in the org tree of the included config are present into the accounts list ????
            # check if referenced SCPs in the org tree of the included config are present into the SCPs list ????
            
            # finally merge org ou tree
            # merge child_spec in spec_object
            ou['Child_OU'] = child_spec['organizational_units'][0]['Child_OU']            
            
            # finally merge accounts
            if 'accounts' in child_spec and child_spec['accounts']:
                if 'accounts' in spec_object and spec_object['accounts']:
                    spec_object['accounts'] += child_spec['accounts']
                else:
                    spec_object['accounts'] = child_spec['accounts']

            # finally merge SCPs
            if 'sc_policies' in child_spec and child_spec['sc_policies']:
                if 'sc_policies' in spec_object and spec_object['sc_policies']:
                    spec_object['sc_policies'] += child_spec['sc_policies']
                else:
                    spec_object['sc_policies'] = child_spec['sc_policies']
     

    return spec_object



def scan_manage_ou_path(spec, path):
    for ou in spec:
        if 'MountingOUPath' in ou:
            ou['Path'] = ou['MountingOUPath']
        else:
            ou['Path'] = path + ou['Name']
        if 'Child_OU' in ou:
            scan_manage_ou_path(ou['Child_OU'], ou['Path'] + '/')

