#!/bin/bash

echo "############ apply:"
set -e

echo "##### run cmd: awsorgs organization --config ./organization/.awsorgs/config.yaml --exec"
awsorgs organization --config ./organization/.awsorgs/config.yaml --exec

echo "##### run cmd: awsaccounts create --config ./organization/.awsorgs/config.yaml --exec"
awsaccounts create --config ./organization/.awsorgs/config.yaml --exec

echo "##### run cmd: awsaccounts update --config ./organization/.awsorgs/config.yaml --exec"
awsaccounts update --config ./organization/.awsorgs/config.yaml --exec
