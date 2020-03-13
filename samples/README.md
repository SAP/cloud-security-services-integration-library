# XSUAA Security Sample Applications


## SAP Java Buildpack
[sap-java-buildpack-api-usage](./sap-java-buildpack-api-usage): Sample demonstrating how to leverage SAP java buildpack to secure a Java web application.

## Java
[java-security-usage](./java-security-usage): Sample demonstrating how to leverage xsuaa as identity service and [java-security](/java-security) library to secure a Java web application and how to test the secured application using the [java-security-test](/java-security-test) test utilities.

[java-tokenclient-usage](./java-tokenclient-usage): Java application demonstrating how to use xsuaa [token-client](/token-client) library for token exchange.

## Spring Boot 2.1 and later
[spring-security-basic-auth](./spring-security-basic-auth): Spring Boot web application demonstrating how a user can access Rest API via basic authentication (user/password).

[spring-security-xsuaa-usage](./spring-security-xsuaa-usage): Sample demonstrating how to leverage xsuaa and spring security library to secure a Spring Boot web application including token exchange (user, client-credentials, refresh, ...).
Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.

[spring-webflux-security-xsuaa-usage](./spring-webflux-security-xsuaa-usage): Sample demonstrating how to leverage xsuaa and spring security library to secure a Spring Boot web application.

## Other Samples
[SAP-samples/teched2019-cloud-cf-product-list](https://github.com/SAP-samples/cloud-cf-product-list): Exercises and documentation on how to integrate with xsuaa in a Node.JS, Java or Spring Boot application.
