
import awsorgs
import awsorgs.orgs
import awsorgs.spec
import awsorgs.accounts

args = {'--auth-account-id': None,
 '--config': '/Users/delhom/gitwork/aws-orgs-fork/docs/.awsorgs.split/master/config.yaml',
 '--debug': 0,
 '--exec': False,
 '--help': False,
 '--master-account-id': None,
 '--org-access-role': None,
 '--quiet': False,
 '--spec-dir': None,
 '--version': False,
 'organization': True,
 'report': False,
 'reverse-setup': False}

# args = {'--auth-account-id': None,
#  '--config': None,
#  '--debug': 0,
#  '--exec': False,
#  '--master-account-id': '677193645847',
#  '--org-access-role': 'Org_Provisioning',
#  '--output-dir': '/Users/delhom/gitwork/axa/awscc-orchestrator-087048844615/prj/CF-foundation/CF-orga-foundation/output_awsorgs',
#  '--quiet': False,
#  '--spec-dir': None,
#  '--template-dir': '/Users/delhom/gitwork/axa/awscc-orchestrator-087048844615/prj/CF-foundation/CF-orga-foundation/spec_init_data',
#  'organization': False,
#  'report': False,
#  'reverse-setup': True,
#  '--force': True}


awsorgs.orgs.core(args)

# '/Users/delhom/gitwork/axa/awscc-orchestrator-087048844615/prj/CF-foundation/awscc-aws-orgs/docs/.awsorgs/config.yaml'


# args = {'--auth-account-id': None,
#  '--config': '/Users/delhom/gitwork/axa/awscc-aws-orgs-fork-428950684324/output_awsorgs/config.yaml',
#  '--debug': 0,
#  '--exec': True,
#  '--help': False,
#  '--invited-account-id': None,
#  '--master-account-id': None,
#  '--org-access-role': None,
#  '--quiet': False,
#  '--spec-dir': None,
#  '--version': False,
#  'create': False,
#  'invite': False,
#  'report': False,
#  'update': True}

# awsorgs.accounts.core(args)


# awsorgs reverse-setup 
# --master-account-id 428950684324 
# --org-access-role OrganizationAccountAccessRole 
# --output-dir ./output_awsorgs 
# --template-dir ./spec_init_data 
# --force --exec
