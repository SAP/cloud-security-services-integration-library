# How to fetch IAS Tokens
  ### With X.509 Client Certificate
  <details>
    <summary>Using curl command</summary>
    
❗Replace the `<<>>` placeholders with the values from the service configuration.   
```shell script
curl --cert certificate.pem --key key.pem -XPOST <<credentials.url>>/oauth2/token \
  -d 'grant_type=password&client_id=<<credentials.clientid>>&username=<<your ias user>>@global.corp.sap&password=<<your ias password>>'
```
    
  </details>
  <details>
    <summary>Using Postman command</summary>
    
1. Store the certificate and key into separate files in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format.
      <br>❗ In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
      ```shell script
         awk '{gsub(/\\n/,"\n")}1' <file>.pem
      ```
2. In Postman navigate to Settings -> Certificates, click on "Add Certificate" and provide the certificate and key `PEM` files and host name.
   <br>![](./postman-mtls.png)
3. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info on how to import it in the Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
4. Fill in the corresponding Postman variables
   <br>![](./postman-variables.png)
5. Open the 'IAS Token | pswd grant' Postman Collection and send the request
  </details>
  
  ### With Client Credentials
  <details>
    <summary>Using curl command</summary>
    
❗Replace the `<<>>` placeholders with the values from the service configuration.  
```shell script   
curl -XPOST https://<<credentials.clientid>>:<<credentials.clientsecret>>@<<credentials.url>>/oauth2/token \
     -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
```
  </details>
  <details>
    <summary>Using Postman command</summary>
    
1. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info how to import it in Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
2. Fill in the corresponding Postman variables
   <br>![](./postman-variables.png)
3. Open the 'Ias Token | pswd grant' Postman Collection and send the request
  </details>

# How to fetch XSUAA Tokens
  ### With X.509 Client Certificate
  <details>
    <summary>Using curl command</summary>
    
❗Replace the `<<>>` placeholders with the values from the service configuration.   
```shell script
curl --cert certificate.pem --key key.pem -XPOST <<VCAP_SERVICES.xsuaa.credentials.certurl>>/oauth/token \
  -d 'grant_type=password&client_id=<<VCAP_SERVICES.xsuaa.credentials.clientid>>&username=<<your xsuaa username>>&password=<<your xsuaa password>>'
```
  </details>
  <details>
    <summary>Using Postman command</summary>

1. Store the certificate and key into separate files in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format.
      <br>❗ In case you experience invalid PEM file errors, \\n characters might have to be replaced by newlines \n to have the PEM in the correct format.
      ```shell script
         awk '{gsub(/\\n/,"\n")}1' <file>.pem
      ```
2. In Postman navigate to Settings -> Certificates, click on "Add Certificate" and provide the certificate and key `PEM` files and host name.
   <br>![](./postman-mtls.png)
3. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info on how to import it in the Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
4. Fill in the corresponding Postman variables
   <br>![](./postman-variables.png)
5. Open the 'Xsuaa Token | pswd grant mTLS' Postman Collection and send the request
    </details>
  
  ### With Client Credentials
  <details>
    <summary>Using curl command</summary>
    
❗Replace the `<<>>` placeholders with the values from the service configuration.   
```
curl -X POST <<VCAP_SERVICES.xsuaa.credentials.url>>/oauth/token \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'client_id=<<VCAP_SERVICES.xsuaa.credentials.clientid>>&client_secret=<<VCAP_SERVICES.xsuaa.credentials.clientsecret>>&grant_type=password&username=<<your xsuaa username>>&password=<<your xsuaa password>>'
```
  </details>
  <details>
    <summary>Using Postman command</summary>
    
1. Import [Postman Collection](./IAS_XSUAA_token_fetch.postman_collection.json). For more info how to import it in Postman see [learning.postman.com](https://learning.postman.com/docs/getting-started/importing-and-exporting-data/#importing-postman-data)
2. Fill in the corresponding Postman variables
   <br>![](./postman-variables.png)
3. Open the 'Xsuaa Token | pswd grant' Postman Collection and send the request

  </details>