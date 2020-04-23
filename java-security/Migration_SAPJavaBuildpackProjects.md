# Migration Guide for J2EE Web Applications that use SAP Java Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java Buildpack.** The SAP Java Buildpack version `x.y.z` does not any longer use Spring and deprecated SAP-internal security libraries. 

This migration document is a step-by-step guide explaining how to replace your dependencies to the deprecated SAP-internal security libraries with the open-sourced ones.

## Prerequisites

Please note, this Migration Guide is only intended for applications, using SAP Java Buildpack. You're using the SAP Java Buildpack, if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.


## Cleanup Maven Dependencies <a name="maven"></a>

Your buildpack application has probably in the `pom.xml` a dependency to one of the deprecated sap-internal security api projects:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | api 
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api 

**If you do not have any of the api projects above as dependency you can skip this guide!**

The above mentioned dependencies should be removed / replaced with those:

```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
    <version>2.6.2</version>
    <scope>provided</scope> <!-- provided with buildpack -->
</dependency>
```

Furthermore, make sure that you do not refer to any other SAP-internal security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 

#### Congratulation! With that you're Done!
You can continue [here](Migration_SAPJavaBuildpackProjects_V2.md) to understand what needs to be done to leverage the new api that is exposed by the SAP Java Buildpack as of version `x.y.z`.


## Further References
- [help.sap.com](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/ead7ee64f96f4c42bacbf0ae23d4135b.html)
- [(SAP-internal) api versions provided with the buildpack](https://wiki.wdf.sap.corp/wiki/display/xs2java/Component+Versions)


