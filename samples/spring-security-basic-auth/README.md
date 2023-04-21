# Spring Security with Basic Auth Sample
This is a sample Spring Boot application secured via Basic Auth that showcases the use of [spring-security](../../spring-security) and [spring-security-starter](../../spring-security-starter).
> :exclamation: Unless absolutely necessary, do not secure your application via Basic Auth as shown in this sample.\
> This sample is only meant for legacy use cases in which the user client does not support OAuth protocols.

For each incoming request, the application accepts user credentials via HTTP Basic Auth and then fetches an XSUAA OAuth2 access token via `Password` grant type.
This is done by implementing Spring's [BearerTokenResolver](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/server/resource/web/BearerTokenResolver.html) interface and configuring the SecurityConfiguration to use it before proceeding with a JWT-based security configuration.\
As a result, the application has access to the user's scopes configured via XSUAA to perform authorization checks. The controller endpoints can be secured as if the request contained the access token directly.

:grey_exclamation: However, securing the application this way comes with several costs.\
Firstly, using `Password` grant type is discouraged because it gives up many of the advantages for which OAuth2 is intended. For example, the user's credentials are available in clear-text to this application.\
Secondly, it is important in an application like this, to cache the users' access tokens for subsequent requests to reduce HTTP traffic and latency. The [Caffeine](https://github.com/ben-manes/caffeine) cache shown in this example is a simple in-memory cache that might be too simple for production. Furthermore, due to caching, administrative changes of a user's privileges, e.g. roles and/or scopes, will not be respected by subsequent requests until the cache has timed out and a new token is fetched for that user. 

## Implementation Notes
Spring's `BearerTokenResolver` interface is implemented in [TokenBrokerResolver](./src/main/java/sample/spring/xsuaa/TokenBrokerResolver.java) which uses the [token-client](../../token-client) module to fetch the access tokens.
Thanks to the autoconfiguration of [spring-security-starter](../../spring-security-starter), a bean of type `XsuaaTokenFlows` is available for injection which is used by the TokenBrokerResolver to perform the `Password` token flow.

In the JUnit tests of this application, a mocked `XsuaaOAuth2TokenService` is used with stubbed responses to provide access tokens for pre-defined user credentials.
To use this service, the TokenBrokerResolver bean is overridden in [TokenBrokerTestConfiguration](./src/test/java/sample/spring/xsuaa/config/TokenBrokerTestConfiguration.java) to make use of it.

In order to get the basic auth login popup, the response header `WWW-Authenticate` must be changed from `Bearer` to `Basic`.
This is done by means of the class `BasicAuthenticationEntryPoint` in the SecurityConfiguration.

## Deployment
Follow the deployment steps for one of the following platforms of your choice.
 
### Kyma/Kubernetes
<details>
<summary>Expand this to see the deployment steps</summary>
  
- Build docker image and push to repository
- Configure the deployment.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

#### Build docker image and push to repository
```shell script
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repositoryName>/<imageName>
docker push <repositoryName>/<imageName>
```

#### Configure the deployment.yml
In deployment.yml, replace the image repository placeholder `<YOUR IMAGE REPOSITORY>` with the one created in the previous step.

#### Deploy the application
Deploy the application using [kubectl cli](https://kubernetes.io/docs/reference/kubectl/)
```shell script
kubectl apply -f ./k8s/deployment.yml -n <YOUR NAMESPACE>
```

#### Cockpit administration tasks: Assign Role Collection to your user
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection `BASIC_AUTH_API_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on https://help.sap.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

#### Access the application
After deployment, the spring service can be called with basic authentication.
```shell
curl -i --user "<SAP ID Service User>:<SAP ID Service Password>" https://spring-security-basic-auth-api.<K8s DOMAIN>/fetchToken
```

As response, you will get a description of the access token as JSON that was fetched with the provided user credentials. Note that the response format is not a JWT.

#### Cleanup
Finally, delete your application and your service instances using the following commands:
```shell script
 kubectl delete -f ./k8s/deployment.yml -n <YOUR NAMESPACE>
```
</details>

### Cloud Foundry
<details>
<summary>Expand this to see the deployment steps</summary>

- Compile the Java application
- Create an XSUAA service instance
- Configure the manifest.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA service instance
:exclamation: If possible, XSUAA should now only be used with X.509 authentication method.

- Use [xs-security.json](./xs-security.json) to create a service instance with X.509 authentication method
- :grey_exclamation: (Deprecated) Use [xs-security-deprecated.json](xs-security-deprecated.json) to create a service instance with client secret authentication method
```shell
cf create-service xsuaa application xsuaa-basic -c xs-security.json
```

## Configure the manifest
The [vars.yml](../vars.yml) contains hosts and paths that need to be specified.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection (`BASIC_AUTH_API_Viewer`) to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on https://help.sap.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).


## Access the application
After deployment, the spring service can be called with basic authentication.
```shell
curl -i --user "<SAP ID Service User>:<SAP ID Service Password>" https://spring-security-basic-auth-<ID>.<LANDSCAPE_APPS_DOMAIN>/fetchToken
```
As response, you will get a description of the access token as JSON that was fetched with the provided user credentials. Note that the response format is not a JWT.

## Clean-Up

Finally, delete your application and your service instances using the following commands:
```
cf delete -f spring-security-basic-auth
cf delete-service -f xsuaa-basic
```
</details>
