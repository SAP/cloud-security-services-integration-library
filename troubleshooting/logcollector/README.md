# logcollector

## Description
The logcollector scripts help you setting the right log levels for troubleshooting your application and application-router.

Therefore it logs you in to your Cloud Foundry Space, sets the log levels for a given application and application router to the values recommended [here (step 12)](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/f22d5100b3a243af88e3edf5311754fc.html) and restarts the given apps.
Then you can replay your scenario. After that the script restores the log levels and restarts the apps again to make sure the changes take effect. It zips the aggregated logs in one file and prints the location to the output.



## Requirements
- Powershell or Bash

## How to use
1. Download (Right-click -> save-link-as) the script according to your shell (Windows: [cf-logcollector.ps1](https://raw.githubusercontent.com/SAP/cloud-security-xsuaa-integration/master/troubleshooting/logcollector/cf-logcollector.ps1), Bash on *nix: [cf-logcollector.sh](https://raw.githubusercontent.com/SAP/cloud-security-xsuaa-integration/master/troubleshooting/logcollector/cf-logcollector.sh))

1. Open your shell and navigate to the script path

1. Execute the script with the following commands: (Keep in mind that this will restart your application and app-router twice!)
    - Powershell: 
        ```
        .\cf-logcollector.ps1 <your-application-name> <your-application-router-name> [path-to-output-zipfile]
        ```
    - Bash: 
        ```
        chmod +x cf-logcollector.sh
        ./cf-logcollector.sh <your-application-name> <your-application-router-name> [path-to-output-zipfile]
        ```
1. Follow the steps in the script
1. The location of the *.zip file will be printed to your output

## Troubleshooting Information
For more information about troubleshooting the XSUAA, please visit the [SAP Help Portal](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/1b3e89e915b349c1aa3896ac8c6becd6.html) or take a look at our [Guided Answers](https://ga.support.sap.com/dtp/viewer/index.html#/tree/2212/actions/28290).