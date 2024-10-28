# SAP BTP Spring Security Client Library with Basic Auth sample application
This Spring Boot sample application is secured via Basic Auth and showcases the use of the [spring-security](/spring-security) and [spring-security-starter](../../spring-security-starter) modules.
> :warning: Unless absolutely necessary, do not secure your application via Basic Auth as shown in this sample.
> 
> This sample is only meant for legacy use cases in which the user client does not support OAuth protocols.

For each incoming request, the application accepts user credentials via HTTP Basic Auth and then fetches an XSUAA OAuth2 access token via `Password` grant type.
This is done by implementing Spring's [BearerTokenResolver](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/server/resource/web/BearerTokenResolver.html) interface and configuring the SecurityConfiguration to use it before proceeding with a JWT-based security configuration.
As a result, the application has access to the user's scopes configured via XSUAA to perform authorization checks.
The controller endpoints can be secured as if the request contained the access token directly.

:grey_exclamation: However, securing the application this way comes at several costs.
Firstly, using `Password` grant type is discouraged because it gives up many of the advantages for which OAuth2 is intended.
For example, the user's credentials are available in clear-text to this application.
Secondly, it is important in an application like this, to cache the users' access tokens for subsequent requests to reduce HTTP traffic and latency.
The [Caffeine](https://github.com/ben-manes/caffeine) cache shown in this example is a simple in-memory cache that might be too simple for production.
Furthermore, due to caching, administrative changes of a user's privileges, e.g. roles and/or scopes, will not be respected by subsequent requests until the cache has timed out and a new token is fetched for that user. 

## Implementation Notes
Spring's `BearerTokenResolver` interface is implemented in [TokenBrokerResolver](./src/main/java/sample/spring/xsuaa/TokenBrokerResolver.java) which uses the [token-client](../../token-client) module to fetch the access tokens.
Thanks to the autoconfiguration of [spring-security-starter](../../spring-security-starter), a bean of type `XsuaaTokenFlows` is available for injection which is used by the TokenBrokerResolver to perform the `Password` token flow.

In the JUnit tests of this application, a mocked `XsuaaOAuth2TokenService` is used with stubbed responses to provide access tokens for pre-defined user credentials.
To use this service, the TokenBrokerResolver bean is overridden in [TokenBrokerTestConfiguration](./src/test/java/sample/spring/xsuaa/config/TokenBrokerTestConfiguration.java) to make use of it.

In order to get the basic auth login popup, the response header `WWW-Authenticate` must be changed from `Bearer` to `Basic`.
This is done by means of the class `BasicAuthenticationEntryPoint` in the SecurityConfiguration.

## Build and Deploy
### 1. The following steps deploy the application using either Cloud Foundry or Kyma/Kubernetes.
<details>
<summary>Deployment on Cloud Foundry</summary>

#### Run maven to compile and package the sample application:
```shell
mvn clean package
```

#### Create the XSUAA service instance
Use the cf CLI to create an XSUAA service instance based on the authentication settings in [xs-security.json](xs-security.json).
```shell
cf create-service xsuaa application xsuaa-basic -c xs-security.json
```

#### Configure the manifest
The [vars](../vars.yml) contain hosts and paths that need to be adapted.

#### Deploy the application
Deploy the application using the cf CLI.

```shell
cf push --vars-file ../vars.yml
```
:warning: This will expect 1 GB of free memory quota.
</details>

<details>
<summary>Deployment on Kubernetes</summary>

#### Build and tag docker image and push to repository
Execute the following docker commands to build and push the docker image to a repository.
Replace `<repository>/<image>` with your repository and image name.
```shell
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repository>/<image>
docker push <repository>/<image>
```

#### Configure the deployment.yml
In deployment.yml replace the placeholder `<YOUR IMAGE TAG>` with the image tag created in the previous step.

:warning: If you are [using a private repository](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/),
you also need to provide the image pull secret in the deployment.yml.

#### Deploy the application
Deploy the application using [kubectl](https://kubernetes.io/docs/reference/kubectl/).
```shell
kubectl apply -f k8s/deployment.yml
```
</details>

### 3. Assign Role Collection to user
:bulb: You can postpone this step if you first want to test the application without the required authorization.

To get full access to the sample application, you need a user having the role collection `Sample Viewer (spring-security-basic-auth)` assigned.
This can be done in the SAP BTP Cockpit or using the btp CLI.

<details>
<summary>Assign role collection via cockpit</summary>
In the cockpit navigate to your subaccount.
To assign the role collection of the sample application to a user you have basically two options:

1. Navigate to the user by clicking on `Security` -> `Users`,
   select the user and click on `Assign Role Collection`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/find-users-and-their-role-collection-assignments)).
2. Navigate to the role collection by clicking on `Security` -> `Role Collections`,
   select `Sample Viewer (spring-security-basic-auth)`,
   click on `Edit` to add the user and finish by clicking on `Save`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/assign-users-to-role-collections)).
</details>

<details>
<summary>Assign role collection via command line</summary>

To assign the role collection to a user via the [btp CLI](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration-using-sap-btp-command-line-interface-btp-cli),
you need to [log in to your global account](https://help.sap.com/docs/btp/btp-cli-command-reference/btp-login) and execute the following command:

```shell
btp assign security/role-collection "Sample Viewer (spring-security-basic-auth)" --subaccount <subaccount id> --to-user <user email>
```
</details>

### 4. Access the application
After deployment, the spring service can be called with basic authentication.
If you have assigned the role-collection as described above, you can access the application via curl.

<details>
<summary>curl command to access Cloud Foundry deployment</summary>

```
curl -i --user "<username>:<password>" \
-X GET https://spring-security-basic-auth-<ID>.<LANDSCAPE_APPS_DOMAIN>/fetchToken
```
</details>

<details>
<summary>curl command to access Kubernetes deployment</summary>

```shell
curl -i --user "<username>:<password>" \
   -X GET https://spring-security-basic-auth-api.<K8s DOMAIN>/fetchToken
```
</details>

:bulb: If you access the application via browser you should be prompted for basic authentication.

As response, you will get a description of the access token as JSON that was fetched with the provided user credentials.
Note that the response format is not a JWT.

### 5. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI or the Kubernetes CLI.

<details>
<summary>Cleanup commands for Cloud Foundry</summary>

```shell
cf delete -f spring-security-basic-auth
cf delete-service -f xsuaa-basic
```
</details>

<details>
<summary>Cleanup command for Kubernetes</summary>

```shell
 kubectl delete -f k8s/deployment.yml
```
</details>
