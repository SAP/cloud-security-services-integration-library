# XSUAA Security Sample Applications


## SAP Java Buildpack
[sap-java-buildpack-api-usage](./sap-java-buildpack-api-usage): Sample demonstrating how to leverage SAP java buildpack to secure a Java J2EE web application.

## Java
[java-security-usage](./java-security-usage): Sample demonstrating how to leverage ``java-security`` library to perform authentication and authorization checks within a Java application when bound to a xsuaa service. Furthermore, it documents how to implement JUnit Tests using `java-security-test` library.
> :white_check_mark: enabled for Kubernetes/Kyma environment<br/>

[java-security-usage-ias](./java-security-usage-ias): Sample demonstrating how to leverage ``java-security`` library to perform authentication checks within a Java application when bound to a ias identity service. Furthermore, it documents how to implement JUnit Tests using `java-security-test` library.

[java-tokenclient-usage](./java-tokenclient-usage): Java application demonstrating how to use xsuaa [token-client](/token-client) library for token exchange.

## Spring Boot 2.1 and later
[spring-security-basic-auth](./spring-security-basic-auth): Spring Boot web application demonstrating how a user can access Rest API via basic authentication (user/password).
> :white_check_mark: enabled for Kubernetes/Kyma environment

[spring-security-xsuaa-usage](./spring-security-xsuaa-usage): Sample demonstrating how to leverage ``spring-xsuaa`` library to secure a Spring Boot web application including token exchange (user, client-credentials, refresh, ...).
Furthermore it documents how to implement SpringWebMvcTests using `java-security-test` library.

[spring-security-hybrid-usage](./spring-security-hybrid-usage): Sample demonstrating how to leverage ```spring-security``` client library to validate jwt tokens issued by ```xsuaa``` service or by ```identity ``` service.
> :white_check_mark: enabled for Kubernetes/Kyma environment

[spring-webflux-security-xsuaa-usage](./spring-webflux-security-xsuaa-usage): Sample demonstrating how to leverage xsuaa and spring security library to secure a Spring Boot web application.

## Other Samples
[SAP-samples/teched2019-cloud-cf-product-list](https://github.com/SAP-samples/cloud-cf-product-list): Exercises and documentation on how to integrate with xsuaa in a Node.JS, Java or Spring Boot application.
