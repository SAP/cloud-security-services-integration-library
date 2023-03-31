[![REUSE status](https://api.reuse.software/badge/github.com/SAP/cloud-security-xsuaa-integration)](https://api.reuse.software/info/github.com/SAP/cloud-security-xsuaa-integration)
[![Java CI with Maven](https://github.com/SAP/cloud-security-xsuaa-integration/actions/workflows/maven.yml/badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/actions/workflows/maven.yml)
[![Fosstars security rating](https://raw.githubusercontent.com/SAP/cloud-security-xsuaa-integration/fosstars-report/fosstars_badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/blob/fosstars-report/fosstars_report.md)
[![CodeQL](https://github.com/SAP/cloud-security-xsuaa-integration/workflows/CodeQL/badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/actions?query=workflow%3ACodeQL)



# SAP BTP Security Services Integration Libraries
This repository offers a comprehensive set of libraries designed to simplify the integration of [SAP Business Technology Platform](https://www.sap.com/products/technology-platform.html) (SAP BTP) security services (XSUAA and Identity Services).
Tailored to support Java EE and Spring Boot applications running on Cloud Foundry or Kubernetes environments.
The libraries focus on streamlining [OAuth 2.0](https://oauth.net) access token validation for tokens issued by XSUAA and Identity Services, in addition, it offers a token-client library to easily fetch tokens without cumbersome setup for http requests and offers also a testing utility that mocks Xsuaa and Identity service behaviour and makes it easy to write integration and unit tests.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Usage](#usage)
   - [2.1 Token Validation](#21-token-validation)
     - [2.1.1 Java EE web applications](#211-Java-EE-web-applications)
     - [2.1.2 Spring Boot applications](#212-spring-boot-web-applications)
   - [2.2 Token Flows](#22-token-flows-for-token-retrievals)
   - [2.3 Testing utilities](#23-testing-utilities)
3. [Installation](#installation)
4. [Troubleshooting](#troubleshooting)
5. [Contributing](#contributing)
6. [License](#license)

## Prerequisites
Before you can use the SAP Cloud Security Services Integration libraries, you must fulfil the following requirements:

1. Knowledge of Java programming and (Optional) Spring Boot framework.
2. Access to an SAP BTP account and the XSUAA or Identity service.
3. Familiarity with OAuth 2.0 and JWT (JSON Web Tokens).
4. Java 17
5. Maven 3.9.0 or later
6. (Optional) Spring Boot 3.0.0 or later, Spring Security 6.0.0 or later if using the Spring integration


## Usage
Typical applications consist of a server providing the HTML content and one or more application serving REST APIs used by the application. Web application use the OAuth Authorization Code Flow for interactive authentication:
1. A user accesses the web application using a browser or mobile device
2. The web application (in typical SAP Business Technology Platform scenario, this is an application router) acts as OAuth client and redirects requests to the OAuth server for authentication
3. Upon authentication, the web application uses the code issued by the authorization server to request an access token
4. The web application uses the access token to request data from the OAuth resource server. The OAuth resource server validates the token using online or offline validation.

![OAuth 2.0 Authorization code flow](docs/oauth.png)

OAuth resource servers (as the one in step 4) require libraries for validating access tokens.

### 2.1. Token Validation
Key features:
* Automatic OAuth2 service configuration based on BTP service bindings found in environment
* OAuth2 Token Validation based on the SAP BTP service binding attributes
* Easy access to principal and token claims within request handlers
* Automatic or sample integrations for common web application frameworks (i.e. Java EE / Spring Security)

#### 2.1.1. Java EE web applications
Developers who need OAuth2 token validation and token access in their Java EE applications can utilize the [java-security](./java-security) library. This library simplifies the process of acquiring token information such as principal and audiences from the security context and takes over token validation for tokens issued by Xsuaa or Identity services.
This library is also integrated in SAP Java Buildpack. 

In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                                                                                                                                                      | 
|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [java-security](/java-security)           | [java-security-xsuaa-usage](/samples/java-security-usage) demonstrates java-security usage with Xsuaa service <br/> [java-security-identity-usage](/samples/java-security-usage-ias) demonstrates java-security usage with Identity service  <br/>    [sap-java-builpack-api-usage](/samples/sap-java-buildpack-api-usage) demonstrates java-security usage with SAP Java Buildpack |

:bulb: Changes with SAP Java Buildpack 1.26.0
The former SAP Java Buildpack versions have used deprecated (Spring) Security libraries and had to be updated. As of version 1.26.0 SAP Java Buildpack uses the [`java-security`](/java-security) library. Please consider these (migration) guides:

- [MANDATORY: clean-up deprecated dependencies](https://github.com/SAP/cloud-security-xsuaa-integration/blob/main/java-security/Migration_SAPJavaBuildpackProjects.md)
- [OPTIONAL: Leverage new APIs and features](https://github.com/SAP/cloud-security-xsuaa-integration/blob/main/java-security/Migration_SAPJavaBuildpackProjects_V2.md)


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
| [token-client](/token-client)             | [java-tokenclient-usage](samples/java-tokenclient-usage) demonstrates usage of token client library in Java EE application<br/>   [spring-security-xsuaa-usage](samples/spring-security-xsuaa-usage) demonstrates usage in Spring Boot application     |              

### 2.3 Testing utilities
For authentication/authorization flow testing purposes there is [java-security-test](/java-security-test) library at your disposal that can be used for unit and integration tests to test the Xsuaa or Identity service client functionality in the application. 
It provides [JwtGenerator](/java-security-test/src/main/java/com/sap/cloud/security/test/JwtGenerator.java) to generate custom JWT tokens that work together with pre-configures [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the Identity or Xsuaa service to fetch JWKS.
With this library you can test end to end all your secured endpoints or app logic that is dependant on information from the tokens.

Key features:
* Generates and signs tokens with user provided attributes
* Provides pre-configured local authorization server that mocks communication with BTP security service to validate self-generated tokens
* For Java EE application sets up local application server that is pre-configured with security filter matching self-generated tokens and which you can configure with the servlets you want to test


In the table below you'll find links to detailed information.

| Library                                   | Usage Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | 
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [java-security-test](/java-security-test) | [Integration test code snippet](/samples/spring-security-hybrid-usage/src/test/java/sample/spring/security/junitjupiter/TestControllerIasTest.java) for Spring application <br/>[Integration test code snippet](/samples/java-security-usage/src/test/java/com/sap/cloud/security/samples/HelloJavaServletIntegrationTest.java) for Java EE web.xml based servlets <br/>  [Integration test code snippet](/samples/java-security-usage-ias/src/test/java/com/sap/cloud/security/samples/ias/HelloJavaServletIntegrationTest.java) for Java EE annotation based servlets <br/>    |

## Installation
The SAP Cloud Security Services Integration is published to maven central: https://search.maven.org/search?q=com.sap.cloud.security and is available as a Maven dependency. Add the following BOM to your dependency management in your `pom.xml`:
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.sap.cloud.security</groupId>
            <artifactId>java-bom</artifactId>
            <version>3.0.0</version>
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
git clone https://github.com/SAP/cloud-security-xsuaa-integration
cd cloud-security-xsuaa-integration
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


## Contributing
We welcome contributions to this project. Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for more details on how to contribute.

## How to get support
Open a [Github issue](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new/choose).

## License
Please see our [LICENSE](LICENSES/Apache-2.0.txt) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available in the [REUSE tool](https://api.reuse.software/info/github.com/SAP/cloud-security-xsuaa-integration).