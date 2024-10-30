# SAP BTP Spring Security Client Library Hybrid sample application
This Spring Boot sample application uses the `spring-security` module to validate JWT tokens issued by either the `xsuaa` or the `identity` service.
The `xsuaa` service provides an OAuth access token, while the `identity` service provides an OIDC token.
The tokens differ in the details they provide through token claims.
In both instances, the validated token is accessible as a [`Token`](/java-api/src/main/java/com/sap/cloud/security/token/Token.java) via the Spring`org.springframework.security.core.context.SecurityContextHolder`.

Additionally, this sample showcases the use of the `CorrelationIdFilter`, which appends a correlation_id to the MDC context.
This is then used to augment subsequent/outgoing requests with an `X-CorrelationID` header.
:link: More information can be found in the [logging filter library documentation](https://github.com/SAP/cf-java-logging-support/wiki/Instrumenting-Servlets).

## Build and Deploy
### 1. Deploy the application on Cloud Foundry or Kyma/Kubernetes.
<details>
<summary>Deployment on Cloud Foundry</summary>

#### Run maven to compile and package the sample application:
```shell
mvn clean package
```

#### Create the XSUAA service instance
Use the cf CLI to create an XSUAA service instance based on the authentication settings in [xs-security.json](xs-security.json).
```shell
cf create-service xsuaa application xsuaa-authn -c xs-security.json
cf create-service xsuaa broker xsuaa-broker -c xs-security-broker.json
```
:grey_exclamation: The `xsuaa-broker` instance is optional.
Use it if you want to test the application with multiple XSUAA service instances.
You would also need to update the [manifest.yml](https://github.com/SAP/cloud-security-services-integration-library/blob/main/samples/spring-security-hybrid-usage/manifest.yml#L20) with the broker instance information.

#### Create the IAS Service Instance
Use the cf CLI to create an Identity service instance
```shell
cf create-service identity application ias-authn
```

#### Configure the manifest
The [vars](../vars.yml) contain hosts and paths that need to be adapted.

#### Deploy the application
Deploy the application using the cf CLI.

```shell
cf push --vars-file ../vars.yml
```
:warning: This will expect 1 GB of free memory quota.
> Note: As service instance gets created asynchronously, you might get the error `There is an operation in progress for the service instance`.
> In this case, wait a moment and try again. 
</details>

<details>
<summary>Deployment on Kubernetes</summary>

#### Build and tag docker image and push to repository
Execute the following commands to build and push the docker image to a repository.
Replace `<repository>/<image>` with your repository and image name.
```shell
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repository>/<image>
docker push <repository>/<image>
```

#### Configure the deployment.yml
In deployment.yml replace the placeholder `<YOUR IMAGE TAG>` with the image tag created in the previous step.

:warning: If you are [using a private repository](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/),
you also need to provide the image pull secret in the deployment.yml.

:bulb: If you want to test the app with multiple Xsuaa bindings (application and broker plan) uncomment the following lines:
- [Service Instance definition and the binding](https://github.com/SAP/cloud-security-services-integration-library/blob/main/samples/spring-security-hybrid-usage/k8s/deployment.yml#L39-L71)
- [Volume mount for the service instance secret](https://github.com/SAP/cloud-security-services-integration-library/blob/main/samples/spring-security-hybrid-usage/k8s/deployment.yml#L127-L129)
- [Volume for the service instance secret](https://github.com/SAP/cloud-security-services-integration-library/blob/main/samples/spring-security-hybrid-usage/k8s/deployment.yml#L138-L140)

#### Deploy the application
Deploy the application using [kubectl](https://kubernetes.io/docs/reference/kubectl/).
```shell
kubectl apply -f k8s/deployment.yml
```
</details>

### 3. Give permission to user
To get access to the sample application, you need a user with one of the following assigned:
- the role collection `Sample Viewer (spring-security-hybrid-usage)' (via XSUAA)
- the group `Read` (via IAS)
:bulb: You can postpone this step if you first want to test the application without the required authorization.

#### Assign Role Collection (XSUAA)
This can be done in the SAP BTP Cockpit or using the btp CLI.

<details>
<summary>Assign role collection via cockpit</summary>
In the cockpit navigate to your subaccount.
To assign the role collection of the sample application to a user you have basically two options:

1. Navigate to the user by clicking on `Security` -> `Users`,
   select the user and click on `Assign Role Collection`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/find-users-and-their-role-collection-assignments)).
2. Navigate to the role collection by clicking on `Security` -> `Role Collections`,
   select `Sample Viewer (spring-security-hybrid-usage)`,
   click on `Edit` to add the user and finish by clicking on `Save`
   (more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/assign-users-to-role-collections)).
</details>

<details>
<summary>Assign role collection via command line</summary>

To assign the role collection to a user via the [btp CLI](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration-using-sap-btp-command-line-interface-btp-cli),
you need to [log in to your global account](https://help.sap.com/docs/btp/btp-cli-command-reference/btp-login) and execute the following command:

```shell
btp assign security/role-collection "Sample Viewer (spring-security-hybrid-usage)" --subaccount <subaccount id> --to-user <user email>
```
</details>

#### Assign group (IAS)
You need administrator permissions to create group `Read` in IAS and assign it to a user.
:link: More information can be found at [SAP Help: "Creating a User Group"](https://help.sap.com/viewer/a339f23ec736441abb2e187b7a7b6afb/LATEST/en-US/64544f432cd24b8589707a5d8a2b3e2e.html).

### 4. Access the application
The sample application provides three HTTP endpoints:

- `/sayHello` - authorized access only
- `/comp/sayHello` - authorized access only
- `/method` - authorized access only (executes a method secured with Spring Global Method Security)

Before sending requests to the above endpoints we need to obtain a valid XSUAA access token or OIDC token for a user.
To this we need to retrieve credentials for the bound XSUAA and IAS service instances from Cloud Foundry or Kubernetes.

<details>
<summary>Retrieve credentials from Cloud Foundry</summary>

Either use the cockpit to navigate to your application (via subaccount and space) and click on 'Environment Variables' or use the cf CLI command
```shell
cf env spring-security-hybrid-usage
```
to retrieve the application environment.
The environment variable `VCAP_SERVICES` contains `credentials` sections for the `xsuaa` and `ìdentity` service instances.
</details>

<details>
<summary>Retrieve credentials from Kubernetes</summary>

Use the following Kubernetes CLI commands to retrieve the `xsuaa` and `ìdentity` service instance credentials.
```shell
kubectl get secret "xsuaa-authn-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}'
kubectl get secret "xsuaa-broker-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}'
kubectl get secret "ias-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}'
```
</details>

Use the credentials to retrieve an XSUAA OAuth access token or OIDC id token for the sample application by following the [HowToFetchToken](../../docs/HowToFetchToken.md) guide.

Now you can use the tokens to access the application via curl.

<details>
<summary>access Cloud Foundry deployment</summary>

```
curl -X GET \
https://spring-security-hybrid-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/sayHello \
-H 'Authorization: Bearer <<access/id token>>'
```

:bulb: You can check the logs using the following cf CLI command:
```shell
cf logs spring-security-hybrid-usage --recent
```
</details>

<details>
<summary>access Kubernetes deployment</summary>

In the Kyma Console, go to your namespace and navigate to `Discovery and Network` &rarr; `API Rules`.
Copy the host entry of the `spring-security-hybrid-api` api rule.

```shell
curl -X GET \
https://<<host of spring-security-hybrid-api>>/sayHello \
-H 'Authorization: Bearer <<access/id token>>'
```
</details>

:bulb: If you call the same endpoints without `Authorization` header you should get a `HTTP 401` response.

### 5. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI or the Kubernetes CLI.

<details>
<summary>Cleanup commands for Cloud Foundry</summary>

```shell
cf unbind-service spring-security-hybrid-usage ias-authn
cf delete -f spring-security-hybrid-usage
cf delete-service -f xsuaa-authn
cf delete-service -f xsuaa-broker
cf delete-service -f ias-authn
```
</details>

<details>
<summary>Cleanup command for Kubernetes</summary>

```shell
 kubectl delete -f k8s/deployment.yml
```
</details>
