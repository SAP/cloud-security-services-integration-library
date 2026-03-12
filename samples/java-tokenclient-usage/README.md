# SAP BTP Java Security Client Library with XSUAA sample application

This Java backend application uses the [token-client](/token-client/) module to request access tokens from `XSUAA` service via the [ClientCredentialsTokenFlow](/token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/ClientCredentialsTokenFlow.java).

**Important:** This sample demonstrates **backward compatibility with Apache HttpClient 4** using deprecated constructors. This approach is supported in version 4.x but will be removed in version 5.0.0.

## About This Sample

This sample showcases how existing applications using Apache HttpClient 4 can continue to work with version 4.0.0+ of the library through deprecated constructors. It serves two purposes:

1. **Testing**: Validates that the backward compatibility layer works correctly
2. **Migration Example**: Shows customers how to temporarily maintain their existing Apache HttpClient 4 integration

### ⚠️ Deprecation Notice

The approach used in this sample relies on deprecated constructors that will be **removed in version 5.0.0**:
- `DefaultOAuth2TokenService(CloseableHttpClient)`
- `DefaultOAuth2TokenKeyService(CloseableHttpClient)`
- `DefaultOidcConfigurationService(CloseableHttpClient)`
- `ApacheHttpClient4Adapter` class

### 📖 Migration Guidance

For production applications, we recommend migrating to one of these approaches:

**Option 1: Use Default Java 11 HttpClient (Recommended)**
```java
// No custom HTTP client needed - works out of the box
DefaultOAuth2TokenService tokenService = new DefaultOAuth2TokenService();
```

**Option 2: Custom HttpRequestExecutor (Future-Proof)**
See the [Apache HttpClient Migration Guide](../../token-client/APACHE_HTTPCLIENT_MIGRATION.md) for implementing custom HTTP clients with any library.

## Code Highlights

The [HelloTokenClientServlet.java](src/main/java/com/sap/cloud/security/xssec/samples/tokenflow/usage/HelloTokenClientServlet.java) demonstrates:

1. **Custom Apache HttpClient 4 configuration** with connection pooling
2. **Using the deprecated constructor** with `@SuppressWarnings("deprecation")`
3. **Proper resource cleanup** in the `destroy()` method
4. **Inline migration comments** showing alternative approaches

There is no authentication done, i.e. the resulting tokens are not related to a user accessing the application. Instead, the access token is issued for the bound service instance on behalf of the application itself.

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
cf create-service xsuaa application xsuaa-token-client -c xs-security.json
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
The sample application provides a single HTTP endpoint:
- `/hello-token-client` - accessible without authentication

<details>
<summary>access Cloud Foundry deployment</summary>

You can access the application at:
```
https://java-tokenclient-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-token-client
```
</details>

<details>
<summary>access Kubernetes deployment</summary>

You can access the application at:
```
https://java-tokenclient-api.<<K8S DOMAIN>>/java-tokenclient-usage/hello-token-client \
```
</details>

You should see something like this:
```
Access-Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8v...
Access-Token-Payload: {"jti":"abcdefghijklmnopqrstuvwxyz123456","ext_attr":{"enhancer":"XSUAA","subaccountid":"...
Expired-At: 2024-10-17T04:31:46.397Z
```

### 4. Cleanup
If you no longer need the sample application, you can free up resources using the cf CLI or the Kubernetes CLI.

<details>
<summary>Cleanup commands for Cloud Foundry</summary>

```shell
cf delete -f java-tokenclient-usage
cf delete-service -f xsuaa-token-client
```
</details>

<details>
<summary>Cleanup command for Kubernetes</summary>

```shell
 kubectl delete -f k8s/deployment.yml
```
</details>
