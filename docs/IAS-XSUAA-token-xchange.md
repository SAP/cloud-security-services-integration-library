# IAS to XSUAA Token exchange
Token exchange supports principal propagation from an IAS-based app/service to a XSUAA-based service, logically staying in the same zone. This is a hybrid scenario of cross consumption between IAS and XSUAA.
In case your application, e.g. a SCP Identity Kernel service supports IAS for authentication, but still needs to support applications using XSUAA. In order to support both token types(IAS, XSUAA) you can simply leverage IAS -> XSUAA token-exchange. As there is no change in API and the setup only requires feature enablement, it takes a little adaption effort.

## Scenario
The user is logged into a multitenant zone-enabled application that performs authentication via IAS identity provider. In the XSUAA multitenancy concept, the zone is mapped to a single XSUAA tenant that belongs to the zone.
The application calls a service in the context of the current user and zone, by sending the IAS ID token for the user. That means the IAS ID token consists of `user_uuid` and `zone_uuid` claim.
The SCP Identity Kernel service uses XSUAA internally and thus needs to exchange the ID token from IAS to an access token from XSUAA.

#### Under the hood
![IAS -> XSUAA token xchange flow diagram](token-xchange.png)

Token of incoming request is checked whether it is a Xsuaa token, if it is Xsuaa token then this token proceeds forward to the token validation step. In case it is valid token, successful response is sent back, otherwise an unauthorized response is sent. 
In case token is not Xsuaa token, application checks if token exchange is enabled, if it is, then Xsuaa access token is requested from Xsuaa instance using the POST request with Header `X-zid`:`zone_uuid`, `grant_type` = `jwt-bearer` and `assertion` = IAS token from the request. Upon successful token exchange between IAS and XSUAA, token gets validated and depending on validation result authorized or unauthorized response is sent back.
In situation when incoming request doesn't contain Xsuaa token and token exchange is disabled, unauthorized response is sent back. 

## Enable token exchange in the application
Set the environment variable `IAS_XSUAA_XCHANGE_ENABLED` to any value, but false or empty. For detailed token exchange setup information please see:
- [spring-xsuaa readme](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/spring-xsuaa#ias-to-xsuaa-token-exchange) for Spring applications
- [java-security readme](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/java-security#ias-to-xsuaa-token-exchange) for Java applications

## Test the setup
#### 1. Setup trust between IAS and Xsuaa
The trust can be setup via
[SCP Cockpit](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/161f8f0cfac64c4fa2d973bc5f08a894.html)

#### 2. Create IAS service broker instance
Create an instance of the IAS service broker

`cf create-service identity application <IAS_SERVICE_INSTANCE_NAME> -c '{"xsuaa-cross-consumption": "true"}'`

> The flag adds the client Id of the trusted XSUAA service, to the audience field of the ID token for cross consumption.

#### 3. Fetch the IAS token
- Create service key for IAS instance if it doesn't exist: `cf create-service-key <IAS_SERVICE_INSTANCE_NAME> <SERVICE_KEY_NAME>`
- Fetch the client credentials: `cf service-key <IAS_SERVICE_INSTANCE_NAME> <SERVICE_KEY_NAME>`
- Request a token:
   ```shell script
   curl POST 'https://iasTenant.accounts400.ondemand.com/oauth2/token' \
   --header 'Authorization: Basic <IAS_CLIENT_ID> <IAS_CLIENT_SECRET>' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=password' \
   --data-urlencode 'username=<YOUR_USERNAME>' \
   --data-urlencode 'response_type=id_token' \
   --data-urlencode 'password=<YOUR_IAS_PSWD>'
   ```
#### 4. Call secured endpoint with an IAS token
Call the secured endpoint with the IAS token like in the example below
   ```shell script
    curl GET 'https://yourApp.cfapps.sap.hana.ondemand.com/yourSecuredEndpoint' \
    --header 'Authorization: Bearer <FETCHED IAS TOKEN>'
   ```
You should receive an authorized response, if everything works fine.

:interrobang: In case of 403 error, check if the user has required role assigned. 
   
## Further details
The **IAS ID token** has following claims:
- `aud` the audiences field that consists of:
    - client id of the IAS application that was configured in the trust setup (this client Id is stored in XSUAA as relying party)
    - client id of the IAS service instance, which is also visible in your `VCAP_SERVICES` in the authorized party `azp` field
the client id of the IAS service instance, which is also visible in your `VCAP_SERVICES`
- `zone_uuid` the zone of your subaccount
- `user_uuid` user id in IAS context :exclamation: not the same as `user_id` in XSUAA

The **Xsuaa access token** after the exchange has the following claims:
- `aud` audience which is the destination service client id 
- `zid` the zone of the subaccount, extracted from claim `zone_uuid` in IAS ID token
