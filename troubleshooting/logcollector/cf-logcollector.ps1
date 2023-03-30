# SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
# SPDX-License-Identifier: Apache-2.0

<#
.Description
    This script changes the log levels of given cloud foundry applications, collect the logs, outputs them to one zip file and resets the log levels again.
.Link
    https://github.com/SAP/cloud-security-xsuaa-integration/troubleshooting/logcollector/
.Parameter App
    Specifies the name of your application.
.Parameter Approuter
    Specifies the name of your application router.
.Parameter Logs
    Specifies the location of the output zip file. $HOME\logcollection.zip is the default.
.Example
    .\cf-logcollector.ps1 my-sample-app my-sample-approuter logs.zip
.Example
    .\cf-logcollector.ps1 -App myapp -Approuter myapprouter -Logs logs.zip
#>
param(
    [Parameter(Mandatory = $True, HelpMessage = "Enter application name.", Position = 0)]
    [String]$App,
    [Parameter(Mandatory = $True, HelpMessage = "Enter application router application name.", Position = 1)]
    [String]$Approuter,
    [Parameter(Mandatory=$false, HelpMessage="Enter path to output zip file.", Position=2)]
    [String]$Logs="$HOME\logcollection.zip",
    [Parameter(Mandatory=$false, HelpMessage="Restore log-levels only?", Position=2)]
    [Switch]$RestoreLogLevelsOnly=$false
)


#Functions
function checkappname() {
    cf app "$args" --guid *> $null
    if (-Not $?) {
        Write-Host "`nApp/Approuter `"$args`" not found, did you target the correct space?"
        break
    }
}
function cflogin() {
    cf login
    if (-Not $?) {
        Write-Host "You need to login to continue. Aborting..."
        break
    }
}
function restoreloglevelsandrestage(){
    Write-Host "`nRestoring log levels...`n"
    cf unset-env "$Approuter" XS_APP_LOG_LEVEL
    cf unset-env "$Approuter" DEBUG
    cf unset-env "$App" SAP_EXT_TRC
    cf unset-env "$App" SAP_EXT_TRL
    cf unset-env "$App" DEBUG

    Write-Host "`nRestage the app and the approuter...`n"
    cf restage "$Approuter"
    cf restage "$App"
}
function setloglevelsandrestage(){
    Write-Host "`nSetting log levels...`n"
    cf set-env "$Approuter" XS_APP_LOG_LEVEL DEBUG
    cf set-env "$Approuter" DEBUG xssec*
    cf set-env "$App" SAP_EXT_TRC stdout
    cf set-env "$App" SAP_EXT_TRL 3
    cf set-env "$App" DEBUG xssec*

    Write-Host "`nRestage the app and the approuter...`n"
    cf restage "$Approuter"
    cf restage "$App"
}
# ---------

#Checking if cf-cli is installed
if (-Not (Get-Command cf)) {
    Write-Host "cf command line client not found, please install cf cli first (https://github.com/cloudfoundry/cli#downloads)."
    break
}

Write-Host "`nAre you already logged in to the CF space you want to work on?`n"
$Title = ""
$Info = "Should we log you on?"
$Options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title, $Info, $Options, $defaultchoice)
switch($opt){
    0 {
      cflogin
    }
    1 {        
    }
}

checkappname "$App"
checkappname "$Approuter"

if($RestoreLogLevelsOnly){
    restoreloglevelsandrestart
}

#Check for restart the apps
Write-Host "`nThis will restage your application " -NoNewline; Write-Host "$App" -ForegroundColor Cyan -NoNewline; Write-Host " and your application router " -NoNewline; Write-Host "$Approuter" -ForegroundColor Cyan -NoNewline; Write-Host " twice."
$Title = ""
$Info = "Are you sure?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title, $Info, $Options, $defaultchoice)
switch ($opt) {
    0 {
        break
    }
    1 {
        Write-Host "`nAborted. Please make sure that it is safe to restage your application before executing the script again."
        exit
    }
}

#Set the enviroment variables and restart the apps
setloglevelsandrestage

#Creating, collecting and compressing the logs
Write-Host "`nNow please repeat your scenario (e.g. try to login to your app or similar)...`n" -ForegroundColor Cyan
Read-Host -Prompt "When you are done please press ENTER to collect the logs"

Write-Host "`nCollecting the logs..."

$tempFile = New-TemporaryFile
Write-Output "Approuter logs:`n`n" *> $tempFile
cf logs "$Approuter" --recent *>> $tempFile
Write-Output "`n`nApp logs:`n`n" *>> $tempFile
cf logs "$App" --recent *>>$tempFile
Compress-Archive -Update -Path $tempFile -DestinationPath "$Logs"
Remove-Item -Path $tempFile

#Unset the enviroment variables and restart the apps
restoreloglevelsandrestage

#End
Write-Host "`nAll done. " -ForegroundColor Green -NoNewline
Write-Host "Your file is here: "
Resolve-Path $Logs
