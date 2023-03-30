#! /usr/bin/env bash
# SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
# SPDX-License-Identifier: Apache-2.0

#functions
usage() { echo -e >&2 "Usage: ./cf-logcollector.sh <app-name> <approuter-name> [output-file]\nIf no output file is specified $HOME/logcollection.zip will be used."; exit 0; }

checkappname() {
	cf app "$1" --guid &>/dev/null || { echo -e >&2 "\nApp/Approuter \"$1\" not found, did you target the correct space?"; exit 1; }
}

#Variables
appname="$1"
approutername="$2"
logszip="$HOME/logcollection.zip"

if [[ -n $3 ]]
then
	logszip="$3"
fi

#Check number of args
if [[ $# -lt 2 || $# -gt 3 ]]
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
echo -e "\nLogging in...\n"
cf login || { echo -e >&2 "\nScript aborted due to failed login. Please check your credentials and try again."; exit 1; }

echo -e "\nSuccessfully logged in, will continue...\n"

checkappname "$appname"
checkappname "$approutername"

printf "\nThis will restart your application \033[36m\033[1m%s\033[0m and your application router \033[36m\033[1m%s\033[0m twice. \nAre you sure (Yy/Nn)?" "$appname" "$approutername"
read -r -p "" answer
if [ "$answer" != "${answer#[Yy]}" ]
then
    true
else
    echo -e "\nAborted. Please make sure that it is safe to restart your application before executing this script again."
	exit 0
fi

#Set the enviroment variables and restart the apps
echo -e "\nSetting log levels...\n"
cf set-env "$approutername" XS_APP_LOG_LEVEL DEBUG
cf set-env "$appname" SAP_EXT_TRC stdout
cf set-env "$appname" SAP_EXT_TRL 3
cf set-env "$appname" DEBUG xssec*

echo -e "\nRestart the app and the approuter...\n"
cf restart "$approutername"
cf restart "$appname"

#Creating, collecting and compressing the logs
echo -e "\n\033[36m\033[1mNow please repeat your scenario (e.g. try to login to your app or similar)...\033[0m\n"
read -rp "When you are done please press ENTER to collect the logs:"

echo -e "\nCollecting the logs..."

{ echo -e "Approuter logs:\n\n"; cf logs "$approutername" --recent; echo -e "\n\nApp logs:\n\n"; cf logs "$appname" --recent; } > /tmp/cflogsoutput

zip -q "$logszip" /tmp/cflogsoutput

rm /tmp/cflogsoutput

#Unsetting env variables and restarting apps
echo -e "\nRestoring log levels...\n"
cf unset-env "$approutername" XS_APP_LOG_LEVEL
cf unset-env "$appname" SAP_EXT_TRC
cf unset-env "$appname" SAP_EXT_TRL
cf unset-env "$appname" DEBUG

echo -e "\nRestart the app and the approuter...\n"
cf restart "$approutername"
cf restart "$appname"

#End
echo -e "\n\033[32m\033[1mAll done.\033[0m Your file is here: " && echo "$logszip"
