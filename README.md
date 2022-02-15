[![REUSE status](https://api.reuse.software/badge/github.com/SAP/cloud-security-xsuaa-integration)](https://api.reuse.software/info/github.com/SAP/cloud-security-xsuaa-integration)
[![Java CI with Maven](https://github.com/SAP/cloud-security-xsuaa-integration/actions/workflows/maven.yml/badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/actions/workflows/maven.yml)
[![Language grade: Java](https://img.shields.io/lgtm/grade/java/g/SAP/cloud-security-xsuaa-integration.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/SAP/cloud-security-xsuaa-integration/context:java)
[![Fosstars security rating](https://raw.githubusercontent.com/SAP/cloud-security-xsuaa-integration/fosstars-report/fosstars_badge.svg)](https://github.com/SAP/cloud-security-xsuaa-integration/blob/fosstars-report/fosstars_report.md)



# Description
Authentication services provided by the xsuaa service on [SAP Cloud Platform](https://cloudplatform.sap.com) or [SAP HANA XS Advanced](https://help.sap.com/viewer/4505d0bdaf4948449b7f7379d24d0f0d/2.0.00/en-US) rely on usage of the [OAuth 2.0](https://oauth.net) protocol and OAuth 2.0 access tokens.

## Web Flow for Authentication
Typical UI5 applications consist of a server providing the HTML content and one or more application serving REST APIs used by the application. Web application use the OAuth Authorization Code Flow for interactive authentication:
1. A user accesses the web application using a browser or mobile device
1. The web application (in typical SAP Cloud Platform applications, this is an application router) acts as OAuth client and redirects to the OAuth server for authorization
1. Upon authentication, the web application uses the code issued by the authorization server to request an access token
1. The web application uses the access token to request data from the OAuth resource server. The OAuth resource server validates the token using online or offline validation.

![OAuth 2.0 Authorization code flow](docs/oauth.png)

OAuth resource servers (as the one in step 4) require libraries for validating access tokens.

## Token Validation for Java web applications using SAP Java Buildpack
The SAP Java Buildpack integrates token validation into the tomcat server. Application developers requiring authentication and authorization information in their application use the interfaces defined in [java-api](./java-api) to obtain information like user name and scopes.

### Requirements
- Java 8 or 11
- maven 3.3.9 or later
- You use `sap_java_buildpack` (e.g. in your `manifest.yml`)

### Sample
See [sap-java-builpack-api-usage](samples/sap-java-buildpack-api-usage) for an example.

### Changes with SAP Java Buildpack 1.26.0
The former SAP Java Buildpack versions have used deprecated (Spring) Security libraries and had to be updated. As of version 1.26.0 SAP Java Buildpack uses the [`java-security`](/java-security) library. Please consider these (migration) guides:

- [MANDATORY: clean-up deprecated dependencies](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-security/Migration_SAPJavaBuildpackProjects.md)
- [OPTIONAL: Leverage new APIs and features](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/java-security/Migration_SAPJavaBuildpackProjects_V2.md)

## Token Exchange for Java applications
Applications requiring access tokens (Jwt) use the Token Flows API defined in [token-client](./token-client) to obtain Jwt tokens for their clients (applications) or for their users.

### Requirements
- Java 8 or 11
- maven 3.3.9 or later

### Sample
- See [java-tokenclient-usage](samples/java-tokenclient-usage) for an example.
- See [spring-security-xsuaa-usage](samples/spring-security-xsuaa-usage) for an example.

## Token Validation for Java applications
Application developers requiring authentication and authorization information in their application use the libraries defined in [java-security](./java-security) to obtain token information like user name.

### Requirements
- Java 8 or 11
- maven 3.3.9 or later

### Sample
See [java-security-usage](samples/java-security-usage) for an example.

### Additional (test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is only intended for JUnit tests.


## Token Validation for Java Spring Boot web applications
Spring Boot provides OAuth resource servers. Application developers requiring authentication and authorization information in their application use the libraries defined in [spring-security](./spring-security) to obtain token information like user name and scopes.

### Requirements
- Java 8 or 11
- maven 3.3.9 or later
- as of version 2.6.1 Spring Boot >= 2.2 is required. Consequently, it also requires Spring Security version >= 5.2

### Sample
- See [spring-security-hybrid-usage](samples/spring-security-hybrid-usage) for an example.
- See [spring-security-basic-auth](/samples/spring-security-basic-auth) for an example demonstrating how a user can access Rest API via basic authentication (user/password) using [spring-xsuaa](./spring-xsuaa).

### Additional (test) utilities
- [java-security-test](./java-security-test) offers test utilities to generate custom JWT tokens for the purpose of tests. It pre-configures a [WireMock](http://wiremock.org/docs/getting-started/) web server to stub outgoing calls to the identity service (OAuth resource-server), e.g. to provide token keys for offline token validation. Its use is only intended for JUnit tests.


# Download and Installation
Build results are published to maven central: https://search.maven.org/search?q=com.sap.cloud.security 

To download and install this project clone this repository via:
```
git clone https://github.com/SAP/cloud-security-xsuaa-integration
cd cloud-security-xsuaa-integration
mvn clean install
```
*Note:* Use this if you want to enhance this xsuaa integration libraries. The build results are also available on maven central.

# Limitations
Libraries and information provided here is around the topic of integrating with the SAP xsuaa and identity service. General integration into other OAuth authorization servers is not the primary focus.

# How to obtain support
Open an issue in GitHub.

# Licensing
Please see our [LICENSE](LICENSES/Apache-2.0.txt) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available via the [REUSE tool](https://api.reuse.software/info/github.com/SAP/cloud-security-xsuaa-integration).
