
echo "############ dryrun:"
set -e

echo "##### run cmd: awsorgs organization --config ./organization/.awsorgs/config.yaml"
awsorgs organization --config ./organization/.awsorgs/config.yaml

echo "##### run cmd: awsaccounts create --config ./organization/.awsorgs/config.yaml"
awsaccounts create --config ./organization/.awsorgs/config.yaml

echo "##### run cmd: awsaccounts update --config ./organization/.awsorgs/config.yaml"
awsaccounts update --config ./organization/.awsorgs/config.yaml
