# logcollector

## Description
The logcollector scripts help you setting the right log levels for troubleshooting your application and application-router.

Therefore it logs you in to your Cloud Foundry Space, sets the log levels for a given application and application router to the values recommended [here](https://wiki.wdf.sap.corp/wiki/display/NWCUIAMSIM/Increase+log+verbosity+for+detailed+error+analysis) and restarts the given apps.
Then you can replay your scenario. After that the script restores the log levels and restarts the apps again to make sure the changes take effect. It zips the aggregated logs in one file and prints the location to the output.



## Requirements
- Powershell or Bash

## How to
1. Download the script according to your shell (Windows: [logcollector.ps1](logcollector.ps1), Bash on *nix: [logcollector.sh](logcollector.sh); Right-click -> save-as)

1. Open your shell and navigate to the script path

1. Execute the script with:
    - Powershell: 
        ```
        .\logcollector.ps1 <your-application-name> <your-application-router-name> [path-to-output-zipfile]
        ```
    - Bash: 
        ```
        ./logcollector.sh <your-application-name> <your-application-router-name> [path-to-output-zipfile]
        ```
1. Follow the steps in the script
1. The location of the *.zip file will be printed to your output
