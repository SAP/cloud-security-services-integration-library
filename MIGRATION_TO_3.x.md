# Migration Guide: SAP Cloud Security Services Integration Library from 2.x to 3.x

This migration guide will help you upgrade your application from 2.x to 3.x Version which involves version upgrades for Java 8, 11 to Java 17 and Spring Boot 2.x to Spring Boot 3.x or Tomcat 9.x to 10.x

## Requirements
* JDK 17
* In case the [SAP Cloud SDK](https://sap.github.io/cloud-sdk/docs/java/overview-cloud-sdk-for-java) is used, the minimum required version for that is `4.14.0`.
  Further details can be found [here](https://sap.github.io/cloud-sdk/docs/java/release-notes).

## Step 1: Migrate from `javax.*` to `jakarta.*` Namespaces
Java EE was transferred from Oracle to the Eclipse Foundation, and the `javax.*` namespace was changed to `jakarta.*`. To migrate your application, follow the [Eclipse Transformer Guide](https://projects.eclipse.org/projects/technology.transformer) to update the affected packages and classes in your codebase.

Alternatively, you can use the [Tomcat Migration Tool for Jakarta](https://github.com/apache/tomcat-jakartaee-migration) to convert your existing `javax.*` applications to `jakarta.*`.

## Step 2: for Java EE based applications - Choose a compatible Tomcat version

To use Java 17 and `jakarta` namespaces, you will need to update your Tomcat version 10.x or later, see [Apache Tomcat Migration Guide for Jakarta](https://tomcat.apache.org/migration-10.html)

### Cloud Foundry Migration

To migrate your Java web application to Java 17 on Cloud Foundry, you'll need to update the Java buildpack. Refer to the [official Cloud Foundry Java buildpack documentation](https://docs.cloudfoundry.org/buildpacks/java/java-tips.html) for instructions on specifying the Java version for your application.

### Kubernetes Migration

To migrate your Java web application to Java 17 on Kubernetes, you'll need to update your Dockerfile or the container image you're using. Replace the base image with a Java 17-based image, such as `openjdk:17-jdk`.

## Step 2 : for Spring Boot based applications - Upgrade to Spring Boot 3 

1. Update your project dependencies to use the latest Spring Boot 3 artifacts. This will likely involve changing the version of your Spring Boot parent POM or updating the Spring Boot version in your build tool configuration. Keep an eye on the [Spring Boot project page](https://spring.io/projects/spring-boot) for the latest release information.
2. Review the [Spring Boot Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide) for any additional changes or requirements specific to Spring Boot 3.
3. Review the [Spring Framework 6.x Migration Guide](https://github.com/spring-projects/spring-framework/wiki/Upgrading-to-Spring-Framework-6.x)
4. Migrate deprecated classes and methods, review the [Spring Boot Release Notes](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Release-Notes#deprecations-in-spring-boot-30) for detailed information

## Step 3: Upgrade Cloud Security Services Integration library
1. **Update dependencies**: Update your project's dependencies to the latest versions of `3.x` of the SAP Cloud Security Services Integration Library. See each library's README for detailed information on required dependencies.
2. **Review deprecated or removed features**: see the [release notes](https://github.com/SAP/cloud-security-services-integration-library/releases/tag/3.0.0) for detailed information about breaking changes and deprecations


## Additional Resources

For more detailed information and help with specific migration issues, refer to the following resources:

1. [Migrating from Java 8 to Java 17 - Official Oracle Guide](https://docs.oracle.com/en/java/javase/17/migrate/getting-started.html)
2. [Jakarta EE 9 Platform Specification](https://jakarta.ee/specifications/platform/9/)
