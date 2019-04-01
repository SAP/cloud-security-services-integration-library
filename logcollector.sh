#! /usr/bin/env bash

#Checking if cf-cli is installed
hash cf 2>/dev/null || { echo >&2 "cf command line client not found, please install cf cli first (https://github.com/cloudfoundry/cli#downloads)."; exit 1; } 
