# SAP BTP Java Security Client Library with XSUAA sample application
This Java backend application uses the [java-security](/java-security/) module to validate JWT tokens issued by the `Identity` service.
It inspects incoming requests and handles authentication and authorization by using the [`IasTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/IasTokenAuthenticator.java).

**Disclaimer: as of now the Identity tokens can only be validated in case the token from the consuming application is issued for the same Identity tenant.**

## Build and Deploy
### 1. Run maven to compile and package the sample application:
```shell
mvn clean package
```

### 2. The following steps deploy the application using either Cloud Foundry or Kyma/Kubernetes.
<details>
<summary>Deployment on Cloud Foundry</summary>

#### Create the IAS service instance
Use the cf CLI to create an IAS service instance.
```shell
cf create-service identity application ias-java-security
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

### 3. Access the application
The sample application provides three HTTP endpoints:
- `/health` - accessible without authentication
- `/hello-java-security-ias` - authenticated access only

Before sending requests to the latter endpoint we need to obtain a valid access token for a user.
To this we need to retrieve the `ias-java-security` service instance credentials from Cloud Foundry or Kubernetes.

<details>
<summary>Retrieve IAS credentials from Cloud Foundry</summary>

Either use the cockpit to navigate to your application (via subaccount and space) and click on 'Environment Variables' or use the cf CLI command
```shell
cf env java-security-usage-ias
```
to retrieve the application environment.
The environment variable `VCAP_SERVICES` contains a `credentials` section for the `xsuaa-java-security` service instance.
</details>

<details>
<summary>Retrieve IAS credentials from Kubernetes</summary>

Use the following Kubernetes CLI command to retrieve the `ias-java-security` service instance credentials by reading the `ias-service-binding` secret.
```shell
kubectl get secret "ias-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}'
```
</details>

Use the IAS credentials to retrieve an access token for the sample application by following the [HowToFetchToken](../../docs/HowToFetchToken.md#ias-tokens) guide.

Now you can use the access token to access the application via curl.

<details>
<summary>curl command to access Cloud Foundry deployment</summary>

```
curl -X GET \
https://java-security-usage-ias-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security-ias \
-H 'Authorization: Bearer <<id token>>'
```
</details>

<details>
<summary>curl command to access Kubernetes deployment</summary>

```shell
curl -X GET \
https://java-security-ias-api.<<K8S DOMAIN>>/java-security-usage-ias/hello-java-security-ias \
-H 'Authorization: Bearer <<access token>>'
```
</details>

You should see something like this:
```
You ('<your user>') can access the application with the following scopes: '<your scopes>'.
```

### 4. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI or the Kubernetes CLI.

<details>
<summary>Cleanup commands for Cloud Foundry</summary>

```shell
cf unbind-service java-security-usage-ias ias-java-security
cf delete -f java-security-usage-ias
cf delete-service -f ias-java-security
```
</details>

<details>
<summary>Cleanup command for Kubernetes</summary>

```shell
 kubectl delete -f k8s/deployment.yml
```
</details>
