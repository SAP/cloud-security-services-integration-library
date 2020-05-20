# Migration Guide for Applications that use SAP Java Buildpack and java-container-security

This migration guide is a step-by-step guide explaining how to replace the following SAP-internal Java Container Security Client libraries
- com.sap.xs2.security:java-container-security
- com.sap.cloud.security.xsuaa:java-container-security  

when using **SAP Java Buildpack**.

## Prerequisite
**Please note, this Migration Guide is only intended for applications using SAP Java Buildpack.**   
You're using the SAP Java Buildpack, if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

## Maven Dependencies
To use the latest SAP-internal `java-container-security` (version `3.2.6`) the dependencies declared in maven `pom.xml` need to be updated.

First make sure you have the following dependencies defined in your pom.xml:

```xml
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>api</artifactId>
  <version>2.7.0</version>
  <scope>provided</scope>
</dependency>
```

Now you are ready to **remove** the **`java-container-security`** client library by deleting the following lines from the pom.xml:
```xml
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
<dependency>
  <groupId>com.sap.xs2.security</groupId>
  <artifactId>java-container-security-api</artifactId>
</dependency>
```
Or
```xml
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>java-container-security</artifactId>
</dependency>
<dependency>
  <groupId>com.sap.cloud.security.xsuaa</groupId>
  <artifactId>api</artifactId>
</dependency>
```

Make sure that you do not refer to any other sap security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 

## Sample
- [J2EE java web servlet sample using SAP Java Buildpack](https://github.com/SAP/cloud-security-xsuaa-integration/tree/master/samples/sap-java-buildpack-api-usage)

## Further References
- [help.sap.com](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/ead7ee64f96f4c42bacbf0ae23d4135b.html)
