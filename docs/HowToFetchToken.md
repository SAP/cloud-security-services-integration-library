# How to fetch tokens
Get your service configuration:
- In CF from [VCAP_SERVICES](https://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html#VCAP-SERVICES) environment variable
- In K8s/Kyma from configuration [secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
## IAS Tokens
<details>
  <summary>Using <b>X.509</b> Client Certificate</summary>
  
1. Store the certificate and key from your service configuration in separate files in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format.
   >❗ In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
   > ```shell script    
   > awk '{gsub(/\\n/,"\n")}1' <file>.pem
   >  ```
 
2. Fetch the token using:

    <details>
      <summary>curl command</summary>
        
    ❗Replace the `<<>>` placeholders with the values from the service configuration.   
    ```shell script
    curl --cert certificate.pem --key key.pem -XPOST <<credentials.url>>/oauth2/token \
      -d 'grant_type=password&client_id=<<credentials.clientid>>&username=<<your ias user>>&password=<<your ias password>>'
    ```
    </details>
    <details>
       <summary>Postman</summary>
            
    1. In Postman navigate to Settings -> Certificates, click on "Add Certificate" and provide the certificate and key `PEM` files and host name.
       <br>![](./postman-mtls.png)
    2. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info on how to import it in the Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
    3. Fill in the corresponding ias_* Postman variables
       <br>![](./postman-variables.png)
    4. Open the 'IAS Token | pswd grant' Postman Collection and send the request
    </details>
</details> 
<details>
  <summary>Using <b>Client Credentials</b></summary>

1. Fetch the token using:
    <details>
        <summary>curl command</summary>
        
    ❗Replace the `<<>>` placeholders with the values from the service configuration.  
    ```shell script   
    curl -XPOST https://<<credentials.clientid>>:<<credentials.clientsecret>>@<<credentials.url>>/oauth2/token \
         -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
    ```
    </details>
    <details>
        <summary>Postman</summary>
        
    1. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info how to import it in Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
    2. Fill in the corresponding ias_* Postman variables
       <br>![](./postman-variables.png)
    3. Open the 'Ias Token | pswd grant' Postman Collection and send the request
    </details>
</details>
  
## XSUAA Tokens
<details>
  <summary>Using <b>X.509</b> Client Certificate</summary>

1. Store the certificate and key from your service configuration in separate files in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format.
   > ❗ In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
   > ```shell script
   > awk '{gsub(/\\n/,"\n")}1' <file>.pem
   > ```
2. Fetch the token using:
    <details>
        <summary>curl command</summary>
        
    ❗Replace the `<<>>` placeholders with the values from the service configuration.   
    ```shell script
    curl --cert certificate.pem --key key.pem -XPOST <<credentials.certurl>>/oauth/token \
      -d 'grant_type=password&client_id=<<credentials.clientid>>&username=<<your xsuaa username>>&password=<<your xsuaa password>>'
    ```
    </details>
    <details>
        <summary>Postman</summary>
    
    1. In Postman navigate to Settings -> Certificates, click on "Add Certificate" and provide the certificate and key `PEM` files and host name.
       <br>![](./postman-mtls.png)
    2. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info on how to import it in the Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
    3. Fill in the corresponding xsuaa_* Postman variables
       <br>![](./postman-variables.png)
    4. Open the 'Xsuaa Token | pswd grant mTLS' Postman Collection and send the request
    </details>
</details>
<details>
   <summary>Using <b>Client Credentials</b></summary>
   
1. Fetch the token using:    
   <details>
     <summary>curl command</summary>
             
   ❗Replace the `<<>>` placeholders with the values from the service configuration.   
   ```
   curl -X POST <<credentials.url>>/oauth/token \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'client_id=<<credentials.clientid>>&client_secret=<<credentials.clientsecret>>&grant_type=password&username=<<your xsuaa username>>&password=<<your xsuaa password>>'
   ```
   </details>
   <details>
       <summary>Using Postman command</summary>
       
   1. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info how to import it in Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
   2. Fill in the corresponding xsuaa_* Postman variables
      <br>![](./postman-variables.png)
   3. Open the 'Xsuaa Token | pswd grant' Postman Collection and send the request
   </details>
</details>
