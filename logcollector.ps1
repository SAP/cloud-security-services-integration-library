<#
.DESCRIPTION
  This script changes the log levels of given cloud foundry applications, collect the logs, outputs them to one zip file and resets the log levels again. See https://github.com/SAP/cloud-security-xsuaa-integration/troubleshooting/logcollector/ for more information.
.USAGE
  ./logcollector.ps1 my-cf-app my-cf-app-router my-output.zip
.PARAM
    appname
    approutername
    [logszip]
.OPTIONS
    -h
.LINK  
    https://github.com/SAP/cloud-security-xsuaa-integration/troubleshooting/logcollector
#>

if (($args.Count -lt 2) -Or ($args.Count -gt 3)) {
    Write-Output "Usage: .\logcollector.ps1 <app-name> <approuter-name> [output-file]`nIf no output file is specified $HOME\logcollection.zip will be used."
    break
}

#Variables
$appname = $args[0]
$approutername = $args[1]

#Write-Output $args.Count

if (-Not  $args[2]) {
    $logszip="$HOME\logcollection.zip"
}

function checkappname() {
    cf app "$args" --guid *> $null
    if (-Not $?) {
        Write-Output "`nApp/Approuter `"$args`" not found, did you target the correct space?"
        break
    }
}

#Checking if cf-cli is installed
if (-Not (Get-Command cf)) {
    Write-Output "cf command line client not found, please install cf cli first (https://github.com/cloudfoundry/cli#downloads)."
    break
}
#login to the correct API endpoint
Write-Output "`nLogging in...`n"
cf login

Write-Output "`nSuccessfully logged in, will continue..."

checkappname "$appname"
checkappname "$approutername"

#Set the enviroment variables and restart the apps
Write-Output "`nSetting log levels...`n"
cf set-env "$approutername" XS_APP_LOG_LEVEL DEBUG
cf set-env "$appname" SAP_EXT_TRC stdout
cf set-env "$appname" SAP_EXT_TRL 3
cf set-env "$appname" DEBUG xssec*

Write-Host "`nThis will restart your application " -NoNewline; Write-Host "$appname" -ForegroundColor Cyan -NoNewline; Write-Host " and your application router " -NoNewline; Write-Host "$approutername" -ForegroundColor Cyan -NoNewline; Write-Host " twice."
$Title = ""
$Info = "Are you sure?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title, $Info, $Options, $defaultchoice)
switch($opt){
    0 {
        Write-Output "`nRestart the app and the approuter...`n"
        cf restart "$approutername"
        cf restart "$appname"
    }
    1 {
        Write-Output "`nAborted. Please make sure that it is safe to restart your application before executing the script again."
        exit
    }
}

#Creating, collecting and compressing the logs
Write-Host "Now please repeat your scenario (e.g. try to login to your app or similar)...`n" -ForegroundColor Cyan
Read-Host -Prompt "When you are done please press ENTER to collect the logs:"

Write-Output "`nCollecting the logs..."