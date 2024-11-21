# How to fetch tokens
Get your service configuration:
- In CF from [VCAP_SERVICES](https://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html#VCAP-SERVICES) environment variable
- In K8s/Kyma from configuration [secrets](https://kubernetes.io/docs/concepts/configuration/secret/)

The documentation assumes the utilities `curl` and `awk` to be installed (Mac OS: brew install curl, Ubuntu: sudo apt-get install curl).

## IAS Tokens
<details>
  <summary>Using X.509 Client Certificate</summary>
  
1. Store the `certificate` and `key` from your service configuration in separate files in [PEM](https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#ftoc-heading-1) format.
   > :warning: In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
   > ```shell
   > awk '{gsub(/\\n/,"\n")}1' <file>.pem
   >  ```
 
2. Fetch the token using:
    ```shell
    curl --cert certificate.pem --key key.pem \
    -X POST <<credentials.url>>/oauth2/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=<<credentials.clientid>>' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'username=<<name of requesting user>>' \
    --data-urlencode 'password=<<password of requesting user>>'
    ```
    :grey_exclamation: Replace the `<<>>` placeholders with values from the service configuration and user credentials.
</details> 
<details>
  <summary>Using Client Credentials</summary>

1. Fetch the token using:
    ```shell
    curl -u '<<credentials.clientid>>:<<credentials.clientsecret>>' \
    -X POST <<credentials.url>>/oauth2/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'username=<<name of requesting user>>' \
    --data-urlencode 'password=<<password of requesting user>>'
    ```
    :grey_exclamation: Replace the `<<>>` placeholders with values from the service configuration and user credentials.
</details>
  
## XSUAA Tokens
<details>
   <summary>Using X.509 Client Certificate</summary>

1. Store the `certificate` and `key` from your service configuration in separate files in [PEM](https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/#ftoc-heading-1) format.
   > :warning: In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
   > ```shell
   > awk '{gsub(/\\n/,"\n")}1' <file>.pem
   > ```
2. Fetch the token using:
      ```shell
      curl --cert certificate.pem --key key.pem \
      -X POST <<credentials.certurl>>/oauth/token \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode 'client_id=<<credentials.clientid>>' \
      --data-urlencode 'grant_type=password' \
      --data-urlencode 'username=<<name of requesting user>>' \
      --data-urlencode 'password=<<password of requesting user>>'
      ```
      :grey_exclamation: Replace the `<<>>` placeholders with values from the service configuration and user credentials.
</details>
<details>
   <summary>Using Client Credentials</summary>
   
1. Fetch the token using:
   ```shell
   curl \
   -X POST <<credentials.url>>/oauth/token \
   -H 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'client_id=<<credentials.clientid>>' \
   --data-urlencode 'client_secret=<<credentials.clientsecret>>' \
   --data-urlencode 'grant_type=password' \
   --data-urlencode 'username=<<name of requesting user>>' \
   --data-urlencode 'password=<<password of requesting user>>'
   ```
   :grey_exclamation: Replace the `<<>>` placeholders with values from the service configuration and user credentials.
</details>
