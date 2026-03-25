# Sample Applications for SAP BTP Cloud Security Service Integration Library

## SAP Java Buildpack
- [sap-java-buildpack-api-usage](./sap-java-buildpack-api-usage): Sample showcasing how to use SAP Java Buildpack to secure a Java J2EE web application.

## Java 17 using Tomcat 10 servlet
- [java-security-usage](./java-security-usage): Sample demonstrating how to use the `java-security` library for authentication and authorization checks in a Java application when bound to an XSUAA service.
Additionally, it explains how to implement JUnit Tests using the `java-security-test` library.
</br>:heavy_check_mark: compatible with Kubernetes/Kyma environment<br/>

- [java-security-usage-ias](./java-security-usage-ias): Sample demonstrating how to use the `java-security` library for authentication checks in a Java application 
when bound to an Identity service. Additionally, it explains how to implement JUnit Tests using the `java-security-test` library.

- [java-tokenclient-usage](./java-tokenclient-usage): Sample demonstrating how to use the Xsuaa [token-client](/token-client) library for token exchange.

## Spring Boot 4.x
- [spring-security-basic-auth](./spring-security-basic-auth): Spring Boot web application demonstrating how a user can access Rest API via basic authentication (user/password).
</br>:heavy_check_mark: enabled for Kubernetes/Kyma environment

- [spring-security-hybrid-usage](./spring-security-hybrid-usage): Sample demonstrating how to leverage ```spring-security``` client library to validate jwt tokens issued by ```Xsuaa``` service or by ```Identity ``` service.
</br>:heavy_check_mark: enabled for Kubernetes/Kyma environment

## Spring Boot 3.x
- [spring-webflux-security-hybrid-usage](./spring-webflux-security-hybrid-usage): Sample demonstrating how to leverage the `spring-security-3` library with Spring WebFlux to validate jwt tokens issued by ```Xsuaa``` service or by ```Identity``` service in a reactive application.
