# Migration Guide for J2EE Web Applications that use SAP Java / XSA Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java / XSA Buildpack.** The SAP Java Buildpack version `1.26.1` does not any longer provide deprecated SAP-internal security libraries and does not longer depend on Spring security. 

This migration document is a step-by-step guide explaining how to replace your dependencies to the deprecated SAP-internal security libraries with the open-sourced ones.

## Prerequisites

Please note, this Migration Guide is only intended for applications using SAP Java Buildpack. You're using the SAP Java Buildpack if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

## Cleanup Maven Dependencies <a name="maven"></a>

First check the `pom.xml` of your application for dependencies to the deprecated sap-internal security api projects:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | java-container-security-api 
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api 

**If you do not have any of the api projects above as dependency you can skip this guide!**

The above mentioned dependencies should be removed / replaced with this one:

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
    <version>2.7.3</version>
    <scope>provided</scope> <!-- provided with buildpack -->
</dependency>
```

Furthermore, make sure that you do not refer to any other SAP-internal security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 

### SAP_JWT_TRUST_ACL obsolete
There is no need to configure `SAP_JWT_TRUST_ACL` within your deployment descriptor such as `manifest.yml`. 
Instead the Xsuaa service instance adds audiences to the issued JSON Web Token (JWT) as part of the `aud` claim.

Whether the token is issued for your application or not is now validated by the [`JwtAudienceValidator`](/java-security/src/main/java/com/sap/cloud/security/token/validation/validators/JwtAudienceValidator.java).


### Congratulation! With that you're Done!

## Issues
In case you face issues to apply the migration steps check this [troubleshoot](README.md#troubleshoot) for known issues and how to file the issue.

## [OPTIONAL] Leverage new API and features
You can continue [here](Migration_SAPJavaBuildpackProjects_V2.md) to understand what needs to be done to leverage the new `java-api` that is exposed by the SAP Java Buildpack as of version `1.26.1`.
