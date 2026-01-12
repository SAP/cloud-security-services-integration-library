[![REUSE status](https://api.reuse.software/badge/github.com/SAP/cloud-security-services-integration-library)](https://api.reuse.software/info/github.com/SAP/cloud-security-services-integration-library)
[![Maven Build main](https://github.com/SAP/cloud-security-services-integration-library/actions/workflows/maven-build.yml/badge.svg?branch=main)](https://github.com/SAP/cloud-security-services-integration-library/actions/workflows/maven-build.yml)
[![Fosstars security rating](https://raw.githubusercontent.com/SAP/cloud-security-xsuaa-integration/fosstars-report/fosstars_badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/blob/fosstars-report/fosstars_report.md)
[![CodeQL](https://github.com/SAP/cloud-security-xsuaa-integration/workflows/CodeQL/badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/actions?query=workflow%3ACodeQL)



# SAP BTP Security Services Integration Libraries
This repository offers a comprehensive set of libraries designed to simplify the integration of [SAP Business Technology Platform](https://www.sap.com/products/technology-platform.html) (SAP BTP) security services (XSUAA and Identity Services).
Tailored to support Jakarta EE and Spring Boot applications running on Cloud Foundry or Kubernetes environments.
The libraries focus on streamlining [OAuth 2.0](https://oauth.net) access token validation for tokens issued by XSUAA and Identity Services. In addition, it offers a token-client library to easily fetch tokens without cumbersome setup for http requests. Finally, it offers testing utility that mocks Xsuaa and Identity service behaviour and makes it easy to write integration and unit tests.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Usage](#usage)
   - [2.1 Token Validation](#21-token-validation)
     - [2.1.1 Jakarta EE web applications](#211-Jakarta-EE-web-applications)
     - [2.1.2 Spring Boot applications](#212-spring-boot-web-applications)
   - [2.2 Token Flows](#22-token-flows-for-token-retrievals)
   - [2.3 Testing utilities](#23-testing-utilities)
   - [2.4 Token Exchange for Hybrid Authentication](#24-token-exchange-for-hybrid-authentication)
       - [2.4.1 Jakarta Example](#241-jakarta-example-using-hybridtokenauthenticator)
       - [2.4.2 Spring Boot Example](#242-spring-boot-example-using-hybridjwtdecoder)
3. [Installation](#installation)
4. [Troubleshooting](#troubleshooting)
5. [Common Pitfalls](#common-pitfalls)
6. [Contributing](#contributing)
7. [How to get support](#how-to-get-support)
8. [License](#license)

## Prerequisites
Before you can use the SAP Cloud Security Services Integration libraries, you must fulfil the following requirements:

1. Knowledge of Java programming and (Optional) Spring Boot framework.
2. Access to an SAP BTP account and the XSUAA or Identity service.
3. Familiarity with OAuth 2.0 and JWT (JSON Web Tokens).
4. Java 17
5. Maven 3.9.0 or later
6. (Optional) Spring Boot 3.0.0 or later, Spring Security 6.0.0 or later if using the Spring integration

:exclamation: For Java 8 and 11 please use [2.x release](https://github.com/SAP/cloud-security-services-integration-library/tree/main-2.x) of this library.

## Usage
Typical web applications consist of a gateway server serving HTML content to the user client and one or more servers behind the gateway providing REST APIs. The gateway server acts as OAuth2 client executing an OAuth2 Authorization Code Flow to retrieve an access token when a new user client session is created. Requests from the user client are correlated with a session id on the gateway server which appends the access token to subsequent requests and forwards them to the REST APIs. The session flow looks as follows:
1. A user accesses the web application using a browser or mobile device which begins a new server session.
2. The web application redirects the user client to the OAuth2 server for authentication. In typical SAP Business Technology Platform scenarios, this is handled by an application router. Upon authentication, the web application receives an authorization code from the user client issued by the OAuth2 server.
3. An access token is retrieved from the OAuth2 server in exchange for the authorization code.
4. The web application uses the access token to access resources on an OAuth2 resource server via a REST API. The OAuth2 resource server validates the token using online or offline validation to restrict access to the API.

![OAuth 2.0 Authorization code flow](docs/oauth.png)

OAuth2 resource servers (as the one in step 4) require libraries for validating access tokens.

### 2.1. Token Validation
Key features:
* Automatic OAuth2 service configuration based on SAP BTP service bindings found in the environment
* OAuth2 Token Validation based on these service configurations
* Easy access to principal and token claims within request handlers
* Automatic or sample integrations for common web application frameworks (i.e. Jakarta EE / Spring Security)

#### 2.1.1. Jakarta EE web applications
Developers who need OAuth2 token validation and token access in their Jakarta EE applications can utilize the [java-security](./java-security) library. This library simplifies the process of acquiring token information such as principal and audiences from the security context and takes over token validation for tokens issued by Xsuaa or Identity services.
This library is also integrated in SAP Java Buildpack. 

In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                                                                                                                                                      | 
|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [java-security](/java-security)           | [java-security-xsuaa-usage](/samples/java-security-usage) demonstrates java-security usage with Xsuaa service <br/> [java-security-identity-usage](/samples/java-security-usage-ias) demonstrates java-security usage with Identity service  <br/>    [sap-java-builpack-api-usage](/samples/sap-java-buildpack-api-usage) demonstrates java-security usage with SAP Java Buildpack |

:bulb: Changes with SAP Java Buildpack 1.26.0
The former SAP Java Buildpack versions have used deprecated (Spring) Security libraries and had to be updated. As of version 1.26.0 SAP Java Buildpack uses the [`java-security`](/java-security) library. Please consider these (migration) guides:

- [MANDATORY: clean-up deprecated dependencies](https://github.com/SAP/cloud-security-services-integration-library/blob/main/java-security/Migration_SAPJavaBuildpackProjects.md)
- [OPTIONAL: Leverage new APIs and features](https://github.com/SAP/cloud-security-services-integration-library/blob/main/java-security/Migration_SAPJavaBuildpackProjects_V2.md)


#### 2.1.2. Spring Boot web applications
Developers seeking OAuth2 token validation and access to token information for their Spring Boot applications can benefit from the [spring-security](/spring-security) library. 
This library streamlines the process of handling token validation for tokens issued by Xsuaa or Identity services and obtaining token details, such as principal and audiences from the security context.

:exclamation: For backward compatibility there is [spring-xsuaa](/spring-xsuaa) library available that supports only Xsuaa service integration, but with the next major release it will be removed. 
- If you're already using [spring-xsuaa](/spring-xsuaa) in your project you should plan the time to migrate to the [spring-security](/spring-security), see [migration guide](/spring-xsuaa/Migration_JavaContainerSecurityProjects.md). 
- If you're just setting up your project you should use [spring-security](/spring-security) library.


In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                           | 
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [spring-security](/spring-security)       | [spring-security-hybrid-usage](samples/spring-security-hybrid-usage) demonstrates usage of xsuaa and Identity service token validation                                                                                                                   |
| [spring-xsuaa](/spring-xsuaa)             | [spring-security-basic-auth](/samples/spring-security-basic-auth) demonstrates how a user can access Rest API via basic authentication (user/password)  <br/>   [spring-xsuaa-usage](/samples/spring-security-xsuaa-usage) demonstrates xsuaa only setup |

### 2.2. Token Flows for token retrievals
Java applications that require access tokens (JWT) from Xsuaa or Identity services can utilize the Token Flows API from the [token-client](./token-client) library, to fetch JWT tokens for their clients (applications) or users.

Typical use cases:
* technical user / system tokens for service to service communication
* user token exchange for principal propagation in service to service communication

In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                         | 
|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [token-client](/token-client)             | [java-tokenclient-usage](samples/java-tokenclient-usage) demonstrates usage of token client library in Jakarta EE application<br/>   [spring-security-xsuaa-usage](samples/spring-security-xsuaa-usage) demonstrates usage in Spring Boot application     |              

### 2.3 Testing utilities
For authentication/authorization flow testing purposes there is [java-security-test](/java-security-test) library at your disposal that can be used for unit and integration tests to test the Xsuaa or Identity service client functionality in the application. 
It provides a [JwtGenerator](/java-security-test/src/main/java/com/sap/cloud/security/test/JwtGenerator.java) to generate custom JWT tokens that work together with a pre-configured [WireMock](http://wiremock.org/docs/getting-started/) web server that stubs outgoing calls to the Identity or Xsuaa service, e.g to fetch the JWKS used to check the validity of the token signature.
With this library you can test end to end all your secured endpoints or app logic that is dependant on information from the tokens.

Key features:
* Generates and signs tokens with user provided attributes
* Provides a pre-configured local authorization server that mocks communication with the BTP security services to validate self-generated tokens
* For Jakarta EE application sets up a local application server that is pre-configured with a security filter matching self-generated tokens. It can be configured to serve the servlets you want to test with mocked authorization


In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | 
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [java-security-test](/java-security-test) | [Integration test code snippet](/samples/spring-security-hybrid-usage/src/test/java/sample/spring/security/junitjupiter/TestControllerIasTest.java) for Spring application <br/>[Integration test code snippet](/samples/java-security-usage/src/test/java/com/sap/cloud/security/samples/HelloJavaServletIntegrationTest.java) for Jakarta EE web.xml based servlets <br/>  [Integration test code snippet](/samples/java-security-usage-ias/src/test/java/com/sap/cloud/security/samples/ias/HelloJavaServletIntegrationTest.java) for Jakarta EE annotation based servlets <br/>    |

### 2.4 Token Exchange for Hybrid Authentication

In hybrid authentication setups, your application can accept tokens from both **SAP Identity Authentication Service (
IAS)** and **XSUAA** simultaneously. This approach eases migration from XSUAA to IAS by exchanging IAS user tokens for
XSUAA tokens behind the scenes.

**Goal**: Maintain backward compatibility during migration. Users authenticate via IAS, but the application continues
using XSUAA-based authorization (scopes, role collections).

#### How Token Exchange Works

```
1. Request arrives with Authorization: Bearer <token>
2. Library identifies issuer (IAS vs XSUAA) from token claims
3. Token validated against appropriate identity service
4. [IF IAS token + exchange enabled]
   ├─ Obtain strong IAS ID token (if access token provided)
   ├─ Call XSUAA /oauth/token endpoint with JWT bearer grant
   └─ Store exchanged XSUAA token in SecurityContext
5. [IF exchange disabled OR XSUAA token]
   └─ Use validated token directly
6. The XSUAA token contains the user's roles/scopes as defined in XSUAA
7. Authorization proceeds using familiar XSUAA token attributes
```

If the incoming token is already an XSUAA token, no exchange occurs—it's validated and used directly.

**Failure Handling**: If token exchange fails (network issues, misconfiguration), authentication fails with 401
Unauthorized. No silent fallback occurs since IAS access tokens typically lack scopes needed for authorization.

#### Token Exchange Modes

The [`TokenExchangeMode`](java-security/src/main/java/com/sap/cloud/security/token/TokenExchangeMode.java)enum controls
when
and how IAS tokens are exchanged:

| Mode                | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`DISABLED`**      | No exchange. Each token type is validated and used as-is.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **`PROVIDE_XSUAA`** | IAS token is validated and exchanged for XSUAA, but the IAS token remains primary in the security context. The XSUAA token is accessible via [`SecurityContext.getXsuaaToken()`](java-api/src/main/java/com/sap/cloud/security/token/SecurityContext.java).                                                                                                                                                                                                                                                   |
| **`FORCE_XSUAA`**   | IAS token is exchanged for XSUAA and the XSUAA token replaces the IAS token in the security context. The resulting security context looks as if an XSUAA token had been received directly.    |

The Initial token is still available via the [`SecurityContext.getInitialToken()`](java-api/src/main/java/com/sap/cloud/security/token/SecurityContext.java) getter and the ID token is available with [`SecurityContext.getIdToken()`](java-api/src/main/java/com/sap/cloud/security/token/SecurityContext.java) 

**Mode Selection Guide**:

- Use **`PROVIDE_XSUAA`** when the app is migrated to AMS authorization and wants to offer combined XSUAA and AMS authorizations for migrated tenants (requires additional configuration of the AMS client library)
- Use **`FORCE_XSUAA`** for maximum backward compatibility—the app operates based on XSUAA tokens like before
- Use **`DISABLED`** or remove the property completely after completing the migration to IAS

#### Prerequisites for Token Exchange

1. Both XSUAA and IAS service bindings must be configured
2. IAS service binding must include `xsuaa-cross-consumption: true` parameter
3. Ensure XSUAA trusts the IAS identity provider

#### 2.4.1 Jakarta Example: Using [`HybridTokenAuthenticator`](java-security/src/main/java/com/sap/cloud/security/servlet/HybridTokenAuthenticator.java)

For Jakarta EE applications, use [
`HybridTokenAuthenticator`](java-security/src/main/java/com/sap/cloud/security/servlet/HybridTokenAuthenticator.java) in
a servlet filter.

For more information, see the [HybridTokenAuthenticator Javadoc](java-security/README.md#hybridtokenauthenticator-usage).

#### 2.4.2 Spring Boot Example: Using [`HybridJwtDecoder`](spring-security/src/main/java/com/sap/cloud/security/spring/token/authentication/HybridJwtDecoder.java)

For Spring Boot applications, [
`HybridIdentityServicesAutoConfiguration`](spring-security/src/main/java/com/sap/cloud/security/spring/autoconfig/HybridIdentityServicesAutoConfiguration.java)
automatically configures hybrid authentication when both IAS and XSUAA bindings are detected.

For more information, see the [HybridJwtDecoder Javadoc](spring-security/README.md#token-exchange-configuration).

#### Important Constraints

**IAS User Tokens Only**: Token exchange only applies to end-user tokens from IAS. Client credentials tokens are **not**
exchanged. Attempting exchange on technical tokens will result in errors.

**Performance**: Exchanged tokens are cached per request and reused until expiration. Caching is automatic and requires
no configuration.

#### Troubleshooting

Common issues and solutions:

| Issue                             | Cause                                          | Solution                                         |
|-----------------------------------|------------------------------------------------|--------------------------------------------------|
| `Token exchange failed` exception | Missing XSUAA binding or invalid configuration | Verify both IAS and XSUAA service bindings exist |
| Exchange returns 401              | IAS binding missing `xsuaa-cross-consumption`  | Add parameter to IAS service binding             |

## Installation
The SAP Cloud Security Services Integration is published to maven central: https://search.maven.org/search?q=com.sap.cloud.security and is available as a Maven dependency. Add the following BOM to your dependency management in your `pom.xml`:
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.sap.cloud.security</groupId>
            <artifactId>java-bom</artifactId>
            <version>3.6.5</version>
            <scope>import</scope>
            <type>pom</type>
        </dependency>
    </dependencies>
</dependencyManagement>
```
along with libraries that you intend to use e.g. `java-security`
```xml
<dependencies>
    <dependency>
        <groupId>com.sap.cloud.security</groupId>
        <artifactId>java-security</artifactId>
    </dependency>
</dependencies>
```
:bulb: Please refer to the Maven Dependencies section in the README.md of the library you intend to use for detailed information on which dependencies need to be added to the `pom.xml`.


If you intend to extend this library you can clone this repository and install this project with `mvn` as follows:
```sh
git clone https://github.com/SAP/cloud-security-services-integration-library
cd cloud-security-services-integration-library
mvn clean install
```

## Troubleshooting
Please refer to each library's Troubleshooting section

| Link to troubleshooting section                               |
|---------------------------------------------------------------|
| [spring-security](/spring-security/README.md#Troubleshooting) |
| [spring-xsuaa](/spring-xsuaa/README.md#Troubleshooting)       |
| [java-security](/java-security/README.md#Troubleshooting)     |
| [token-client](/token-client/README.md#Troubleshooting)       |

## Common Pitfalls
### java.lang.NoSuchMethodError and java.lang.ClassNotFoundException errors
Most common reason for these errors are out of sync client library versions. All the modules of the Security Client libraries
should be always in the same version. 
This can be verified by executing `mvn dependency:tree` command.

The easiest way to manage the module versions and keep them in sync is to use the [BOM](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#bill-of-materials-bom-poms)

The usage of the Security Client Libraries BOM is demonstrated also in the [spring-security-hybrid-usage sample](https://github.com/SAP/cloud-security-services-integration-library/blob/main/samples/spring-security-hybrid-usage/pom.xml#L35-L45)

### reference-instance plan not supported
The `reference-instance` plan is not an original plan of the Xsuaa service, therefore it is not supported by the Security Client Libraries out of the box.
For a workaround please refer to the https://github.com/SAP/cloud-security-services-integration-library/issues/1279#issuecomment-1735542987

## Contributing
We welcome contributions to this project. Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for more details on how to contribute.

## How to get support

**Support is no longer provided via the Issues feature in this Github repository.**

Please use SAP official support channels to get support under component `BC-CP-CF-SEC-LIB` or `Security Client Libraries`.

Before opening support tickets, please check the [Troubleshooting](#troubleshooting) and [Common Pitfalls](#common-pitfalls) sections first in addition to the READMEs of the modules that you are using from this repository.

Make sure to include the following mandatory information to get a response:

- List of module(s) of this library used by your application (java-security, spring-security, spring-xsuaa etc...) and version of this library installed in your application.\
  *Alternative*: maven dependency tree
- Auth service set-up of your application (XSUAA, IAS, XSUAA+IAS, IAS+AMS, etc.)
- For exceptions: Stack trace that includes the executed code locations of this library that lead to the exception
- For unexpected 401 / 403 response codes: relevant log output of this library with active DEBUG flag (see module READMEs for a guide how to enable it)
- Steps you have tried to fix the problem
- Reason why you believe a bug in this library is causing your problem

Unfortunately, we can *NOT* offer consulting via support channels.

## License
Please see our [LICENSE](LICENSES/Apache-2.0.txt) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available in the [REUSE tool](https://api.reuse.software/info/github.com/SAP/cloud-security-xsuaa-integration).
