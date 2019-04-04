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
    Write-Host "Usage: .\logcollector.ps1 <app-name> <approuter-name> [output-file]`nIf no output file is specified $HOME\logcollection.zip will be used."
    break
}

#Variables
$appname = $args[0]
$approutername = $args[1]

#Write-Output $args.Count

if (-Not  $args[2]) {
    $logszip="$HOME\logcollection.zip"
} else {
    $logszip = $args[2]
}

function checkappname() {
    cf app "$args" --guid *> $null
    if (-Not $?) {
        Write-Host "`nApp/Approuter `"$args`" not found, did you target the correct space?"
        break
    }
}

#Checking if cf-cli is installed
if (-Not (Get-Command cf)) {
    Write-Host "cf command line client not found, please install cf cli first (https://github.com/cloudfoundry/cli#downloads)."
    break
}
#login to the correct API endpoint
Write-Host "`nLogging in...`n"
cf login

Write-Host "`nSuccessfully logged in, will continue..."

checkappname "$appname"
checkappname "$approutername"

Write-Host "`nThis will restart your application " -NoNewline; Write-Host "$appname" -ForegroundColor Cyan -NoNewline; Write-Host " and your application router " -NoNewline; Write-Host "$approutername" -ForegroundColor Cyan -NoNewline; Write-Host " twice."
$Title = ""
$Info = "Are you sure?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title, $Info, $Options, $defaultchoice)
switch($opt){
    0 {
        break
    }
    1 {
        Write-Host "`nAborted. Please make sure that it is safe to restart your application before executing the script again."
        exit
    }
}

#Set the enviroment variables and restart the apps
Write-Host "`nSetting log levels...`n"
cf set-env "$approutername" XS_APP_LOG_LEVEL DEBUG
cf set-env "$appname" SAP_EXT_TRC stdout
cf set-env "$appname" SAP_EXT_TRL 3
cf set-env "$appname" DEBUG xssec*

Write-Host "`nRestart the app and the approuter...`n"
cf restart "$approutername"
cf restart "$appname"

#Creating, collecting and compressing the logs
Write-Host "`nNow please repeat your scenario (e.g. try to login to your app or similar)...`n" -ForegroundColor Cyan
Read-Host -Prompt "When you are done please press ENTER to collect the logs"

Write-Host "`nCollecting the logs..."

$tempFile = New-TemporaryFile
Write-Output "Approuter logs:`n`n" *> $tempFile
cf logs "$approutername" --recent *>> $tempFile
Write-Output "`n`nApp logs:`n`n" *>> $tempFile
cf logs "$appname" --recent *>>$tempFile
Compress-Archive -Update -Path $tempFile -DestinationPath "$logszip"
Remove-Item -Path $tempFile

#Unset the enviroment variables and restart the apps
Write-Host "`nRestoring log levels...`n"
cf unset-env "$approutername" XS_APP_LOG_LEVEL
cf unset-env "$appname" SAP_EXT_TRC
cf unset-env "$appname" SAP_EXT_TRL
cf unset-env "$appname" DEBUG

Write-Host "`nRestart the app and the approuter...`n"
cf restart "$approutername"
cf restart "$appname"

#End
Write-Host "`nAll done." -ForegroundColor Green -NoNewline
Write-Host "Your file is here: "
Resolve-Path $logszip