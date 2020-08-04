#!/bin/bash

echo "build start"
echo "############ reports:"

echo "##### run cmd: awsorgs report --config ./organization/.awsorgs/config.yaml"
{ # try
    awsorgs report --config ./organization/.awsorgs/config.yaml > ./awsorgs-report.log && echo "##### cmd output:"
    #save your output
} || { # catch
    echo "##### cmd output (with error):"
    # save log for exception 
}
cat ./awsorgs-report.log

echo "#### run cmd: awsaccounts report --config ./organization/.awsorgs/config.yaml"
{ # try
    awsaccounts report --config ./organization/.awsorgs/config.yaml > ./awsaccounts-report.log && echo "##### cmd output:"
    #save your output
} || { # catch
    echo "##### cmd output (with error):"
    # save log for exception 
}
cat ./awsaccounts-report.log
