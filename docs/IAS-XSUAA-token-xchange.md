#IAS to XSUAA Token exchange
Token exchange supports principal propagation from an IAS-based app/service to an XSUAA-based service, logically staying in the same zone.
This is a hybrid scenario of cross consumption between IAS and XSUAA to support transition away from XSUAA.

###Scenario
The user is logged in to a multitenant application that has adopted IAS and zones.
The application (or an internally used reuse service) calls a reuse service in the context of the current user and zone, by sending the IAS ID token for the user. That means the IAS ID token consists of "user_uuid" and "zone_uuid" claim.
The reuse service uses XSUAA internally and thus needs to exchange the ID token from IAS to an access token from XSUAA. 
In the XSUAA multitenancy concept, the zone is mapped to the single XSUAA tenant that belongs to the zone (=> XSUAA tenant ID = zone ID).

###Under the hood
![IAS -> XSUAA token xchange flow diagram](token-xchange.png)

Token of incoming request is checked whether it is a Xsuaa token, if it is Xsuaa token then this token proceeds forward to the token validation step. In case it is valid token, successful response is sent back, otherwise an unauthorised response is sent. 
In case token is not Xsuaa token, application checks if token exchange is enabled, if it is, then Xsuaa access token is requested from Xsuaa instance using the IAS token from the request. Upon successful token exchange between IAS and XSUAA, token gets validated and depending on validation result authorised or unauthorised response is sent back.
In situation when incoming request doesn't contain Xsuaa token and token exchange is disabled, unauthorised response is sent back. 
###Setup
1. Setup trust between IAS and Xsuaa (detailed information can be found [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/161f8f0cfac64c4fa2d973bc5f08a894.html))
   1. create an XSUAA service instance with plan apiaccess in your subaccount
   2. fetch access token from this service instance
   3. execute the trust setup:
   ```shell script
    curl --location --request POST 'https://api.authentication.sap.hana.ondemand.com/sap/rest/identity-providers' \
    --header 'Authorization: bearer <FETCHED TOKEN FROM APIACCESS>' \
    --header 'Content-Type: application/json' \
    --header 'Accept: application/json' \
    --data-raw '{
        "type":"oidc1.0",
              "config":{
                 "iasTenant": {
                   "host": "<your IAS Tenant Hostname>"
                 }
              }
           }'
   ```
2. Create IAS service broker instance
   1. Create an instance of the IAS service broker and bind it to the application
   2. Set the xsuaa cross consumption flag to true
   ```json
    {"xsuaa-cross-consumption": "true"}
    ```
    > The flag adds the client Id of the IAS application, that was created during trust setup by XSUAA, to the audience field of the token for cross consumption.
3. Enable token exchange in the application by setting the environment variable `IAS_XSUAA_XCHANGE_ENABLED` to any value, but false or empty. For detailed token exchange setup information please see:
   - [spring-xsuaa readme](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa#ias-to-xsuaa-token-exchange) for Spring applications
   - [java-security readme](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/java-security#ias-to-xsuaa-token-exchange) for Java applications
4. To test: call a secured endpoint with an IAS token
    1. Fetch the IAS token using the service key for the IAS service instance
    2. Call the secured endpoint with the IAS token like in the example below
   ```shell script
    curl --location --request GET 'https://spring-security-xsuaa-usage.cfapps.sap.hana.ondemand.com/v1/sayHello' \
    --header 'Authorization: Bearer your.ias.token' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json'
   ```
   You should receive an authorised response.
   
#### Additional info about claims
The **IAS ID token** has following claims:
- **"aud"** the audiences field that consists of:
    - client id of the IAS application that was configured in the trust setup (this client Id is stored in XSUAA as relying party)
    - client id of the IAS service instance, which is also visible in your VCAP_SERVICES in the authorized party ("azp") field
the client id of the IAS service instance, which is also visible in your VCAP_SERVICES
- **"zone_uuid"** the zone of your subaccount 

The **Xsuaa access token** after the exchange has the following claims:
- **"aud"** audience which is the destination service client id 
- **"azp"** authorized parties
- **"zid"** which is the zone of the subaccount