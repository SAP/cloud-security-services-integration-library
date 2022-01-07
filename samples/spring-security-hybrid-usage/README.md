# Description
This spring boot application sample uses ```spring-security``` client library to validate jwt tokens issued by ```xsuaa``` service or by ```identity ``` service. On the one hand ```xsuaa``` service issues an access token and on the other hand ```identity``` service issues an oidc token. The tokens vary with regard to the information provided via token claims. In both cases the validated token is available of type [```Token```](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-api/src/main/java/com/sap/cloud/security/token/Token.java) via the ```SecurityContextHolder```.
This sample also demonstrates usage of `CorrelationIdFilter` that adds correlation_id to MDC context that is used to enhance subsequent/outgoing requests with `X-CorrelationID` header. More information about logging filter library used can be found [here](https://github.com/SAP/cf-java-logging-support/wiki/Instrumenting-Servlets).

# Coding
This sample is using the [`spring-security`](/spring-security/) library, which is based on [Spring's Security](https://github.com/spring-projects/spring-security) project and runs on SAP Cloud Business Technology Platform. It integrates with [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver). The security configuration needs to configure jwt for authentication.


Follow the deployment steps for [Kyma/Kubernetes](#Deployment-on-Kyma/Kubernetes) or [Cloud Foundry](#Deployment-on-Cloud-Foundry).

# Deployment on Kyma/Kubernetes
<details>
<summary>Expand this to follow the deployment steps</summary>

- Build docker image and push to repository
- Configure the deployment.yml
- Deploy the application
- Admin: Assign Role Collection to your XSUAA user
- Admin: Assign Group to your IAS user
- Access the application

## Build docker image and push to repository
```shell script
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repositoryName>/<imageName>
docker push <repositoryName>/<imageName>
```
> This makes use of `Dockerfile`.

## Configure the deployment.yml
In deployment.yml replace the image repository placeholder `<YOUR IMAGE REPOSITORY>` with the one created in the previous step.

## Deploy the application
Deploy the application using [kubectl cli](https://kubernetes.io/docs/reference/kubectl/)
```shell script
kubectl apply -f ./k8s/deployment.yml -n <YOUR NAMESPACE>
```

## Cockpit administration task: Assign Xsuaa Role Collection to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection `XSUAA-Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## IAS User administration task: Assign Group to your User
You need administrator permissions to create Groups "Read" in IAS and assign it to your user. <br>See also [SAP Help: "Creating a User Group"](https://help.sap.com/viewer/a339f23ec736441abb2e187b7a7b6afb/LATEST/en-US/64544f432cd24b8589707a5d8a2b3e2e.html).

## Access the application
1. Follow [HowToFetchToken](../../docs/HowToFetchToken.md) guide to fetch IAS and XSUAA tokens. 
    1. Get an IAS oidc token via ``password`` grant token flow.
       You can get the information to fill the placeholders from the service binding secret:
       ```shell script
       kubectl get secret "ias-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}' -n <YOUR NAMESPACE>
       ```
    2. Get a XSUAA access token via ``client-certificate`` token flow.
       You can get the information to fill the placeholders from the service binding secret: 
       ```shell script
       kubectl get secret "xsuaa-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}' -n <YOUR NAMESPACE>
       ```
2. In the Kyma Console, go to `<YOUR_NAMESPACE>` - `Discovery and Network` - `API Rules`. Copy the host entry of the `spring-security-hybrid-api` api rule.
 
3. Call the following endpoints with ```Authorization``` header = "Bearer <your IAS/XSUAA token>"
   - `<HOST of spring-security-hybrid-api>/sayHello` - GET request that provides token details, but only if token provides expected read permission (scope/groups).
   - `<HOST of spring-security-hybrid-api>/method` - GET request executes a method secured with Spring Global Method Security, user requires read permission (scope/groups).
   
   :bulb: If you call the same endpoint without `Authorization` header you should get a `401`.

## Cleanup
Finally, delete your application and your service instances using the following command:
```shell script
 kubectl delete -f ./k8s/deployment.yml -n <YOUR NAMESPACE>
```
 </details>

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Create a XSUAA service instance
- Create an Identity service instance
- Configure manifest.yml
- Compile and deploy the application
- Admin: Assign Role Collection to your XSUAA user
- Admin: Assign Group to your IAS user
- Access the application


## Create the XSUAA Service Instance
Use the [xs-security.json](./xs-security.json) to define the X.509 authentication method with Xsuaa managed certificate and create a service instance
```shell
cf create-service xsuaa application xsuaa-authn -c xs-security.json
```

## Create the IAS Service Instance
Use the ias service broker and create an identity service instance
```shell
cf create-service identity application ias-authn
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that you might need to adopt.

## Compile and deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
mvn clean package
cf push --vars-file ../vars.yml
```
> Note: In case of this error message `An operation for service instance ias-authn is in progress.` wait a moment, as identity service instance gets created asynchronously.

## Cockpit administration task: Assign Xsuaa Role Collection to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection(s) such as `XSUAA-Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## IAS User administration task: Assign Group to your User
You need administrator permissions to create a Groups "Read" in IAS and assign it to your user.

## Access the application
1. Follow [HowToFetchToken](../../docs/HowToFetchToken.md) guide to fetch IAS and XSUAA tokens. 
    1. Get an IAS oidc token via ``password`` grant token flow.
       You can get the information to fill the placeholders from your system environment `cf env spring-security-hybrid-usage` -> ``VCAP_SERVICES``.`identity`

    2. Get a XSUAA access token via ``client-certificate`` token flow.
       You can get the information to fill the placeholders from your system environment `cf env spring-security-hybrid-usage` -> ``VCAP_SERVICES``.`xsuaa`

2. Call the following endpoints with ```Authorization``` header = "Bearer <your IAS/XSUAA token>"
   - `https://spring-security-hybrid-usage-<ID>.<LANDSCAPE_APPS_DOMAIN>/sayHello` - GET request that provides token details, but only if token provides expected read permission (scope/groups).
   - `https://spring-security-hybrid-usage-<ID>.<LANDSCAPE_APPS_DOMAIN>/method` - GET request executes a method secured with Spring Global Method Security, user requires read permission (scope/groups).

   :bulb: If you call the same endpoint without `Authorization` header you should get a `401`.

3. Have a look into the logs with:
   ```
   cf logs spring-security-hybrid-usage --recent
   ```

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-hybrid-usage
cf delete-service -f xsuaa-authn
cf delete-service -f ias-authn
```
