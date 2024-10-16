# SAP BTP Java Security Client Library with XSUAA sample application
This Java backend application uses the [java-security](../../java-security/) module to validate JWT tokens issued by the `XSUAA` service.
It inspects incoming requests and handles authentication and authorization by using the [`XsuaaTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/XsuaaTokenAuthenticator.java).

## Build and Deploy
### 1. Run maven to compile and package the sample application:
```shell
mvn clean package
```

### 2. The following steps deploy the application using either Cloud Foundry or Kyma/Kubernetes.
<details>
<summary>Deployment on Cloud Foundry</summary>

#### Create the XSUAA service instance
Use the cf CLI to create an XSUAA service instance based on the authentication settings in [xs-security.json](./xs-security.json).
```shell
cf create-service xsuaa application xsuaa-java-security -c xs-security.json
```

#### Configure the manifest
The [vars](../vars.yml) contain hosts and paths that need to be adopted.

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
docker build -t <repository>/<image> .
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

To get full access to the sample application, you need a user having the role collection `Sample Viewer (java-security-usage)` assigned.
This can be done in the SAP BTP Cockpit or using the btp CLI.

<details>
<summary>Assign role collection via cockpit</summary>
In the cockpit navigate to your subaccount.
To assign the role collection of the sample application to a user you have basically two options:

1. Navigate to the user by clicking on `Security` -> `Users`,
select the user and click on `Assign Role Collection`
(more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/find-users-and-their-role-collection-assignments)).
2. Navigate to the role collection by clicking on `Security` -> `Role Collections`,
select `Sample Viewer (java-security-usage)`,
click on `Edit` to add the user and finish by clicking on `Save`
(more info at [help.sap.com](https://help.sap.com/docs/btp/sap-business-technology-platform/assign-users-to-role-collections)).
</details>

<details>
<summary>Assign role collection via command line</summary>

To assign the role collection to a user via the [btp CLI](https://help.sap.com/docs/btp/sap-business-technology-platform/account-administration-using-sap-btp-command-line-interface-btp-cli),
you need to [log in to your global account](https://help.sap.com/docs/btp/btp-cli-command-reference/btp-login) and execute the following command:

```shell
btp assign security/role-collection "Sample Viewer (java-security-usage)" --subaccount <subaccount id> --to-user <user email>
```
</details>

### 4. Access the application
The sample application provides three HTTP endpoints:
- `/health` - accessible without authentication
- `/hello-java-security` - authenticated access only
- `/hello-java-security-authz` - authorized access only

Before sending requests to the latter two endpoints we need to obtain a valid access token for a user.
To this we need to retrieve the `xsuaa-java-security` service instance credentials from Cloud Foundry or Kubernetes.

<details>
<summary>Retrieve XSUAA credentials from Cloud Foundry</summary>

Either use the cockpit to navigate to your application (via subaccount and space) and click on 'Environment Variables' or use the cf CLI command
```shell
cf env java-security-usage
```
to retrieve the application environment.
The environment variable `VCAP_SERVICES` contains a `credentials` section for the `xsuaa-java-security` service instance.
</details>

<details>
<summary>Retrieve XSUAA credentials from Kubernetes</summary>

Use the following Kubernetes CLI command to retrieve the `xsuaa-java-security` service instance credentials by reading the `xsuaa-service-binding` secret.
```shell
kubectl get secret "xsuaa-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}'
```
</details>

Use the XSUAA credentials to retrieve an access token for the sample application by following the [HowToFetchToken](../../docs/HowToFetchToken.md#xsuaa-tokens) guide.

Now you can use the access token to access the application via curl.

<details>
<summary>curl command to access Cloud Foundry deployment</summary>

```
curl -X GET \
https://java-security-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security \
-H 'Authorization: Bearer <<access token>>'
```
</details>

<details>
<summary>curl command to access Kubernetes deployment</summary>

```shell
curl -X GET \
https://java-security-api.<<K8S DOMAIN>>/java-security-usage/hello-java-security \
-H 'Authorization: Bearer <<access token>>'
```
</details>

You should see something like this:
```
You ('<your user>') can access the application with the following scopes: '<your scopes>'.
```

### 5. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI or the Kubernetes CLI.

<details>
<summary>Cleanup commands for Cloud Foundry</summary>

```shell
cf delete -f java-security-usage
cf delete-service -f xsuaa-java-security
```
</details>

<details>
<summary>Cleanup command for Kubernetes</summary>

```shell
 kubectl delete -f k8s/deployment.yml
```
</details>
