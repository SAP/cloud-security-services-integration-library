#! /usr/bin/env bash

#functions
usage() { echo >&2 -e "Usage: ./logcollector.sh <app-name> [<approuter-name]>]"; exit 0; }

#Check number of args
if [[ $# -eq 0 || $# -gt 2 ]]
then
	usage
	exit 1
fi

while getopts "h" arg; do
    case "$arg" in
        h | *)
           	 usage
           	 ;;
    esac
done
shift $((OPTIND-1))

#Checking if cf-cli is installed
hash cf 2>/dev/null || { echo >&2 "cf command line client not found, please install cf cli first (https://github.com/cloudfoundry/cli#downloads)."; exit 1; }

#login to the correct API endpoint
cf login || { echo -e >&2 "\nScript aborted due to failed login. Please check your credentials and try again."; exit 1; }

echo -e "\nSuccessfully logged in, will continue..."

cf app "$1" --guid &>/dev/null || { echo -e >&2 "\nApp $1 not found, did you target the correct space?"; exit 1; }
