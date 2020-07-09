# Migration Guide for J2EE Web Applications that use SAP Java Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java Buildpack.** The SAP Java Buildpack version `1.26.1` does not any longer provide deprecated SAP-internal security libraries and does not longer depend on Spring security. 

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

## Troubleshoot

If you get stuck with migrating your application, 
[open an issue on Github](https://github.com/SAP/cloud-security-xsuaa-integration/issues/new)
and provide these details 
- migration guide, e.g. java-security/Migration_SAPJavaBuildpackProjects.md
- client-lib version you have used before, e.g. com.sap.cloud.security.xssec:api version 3.11.0
- client-lib version you have migrated to, e.g. com.sap.cloud.security.xsuaa:api version 2.7.3
- [SAP buildpack version](#get-buildpack-version), e.g. 1.26.1 
- [debug logs](#increase-log-level-to-debug)
- issue you’re facing.

### Get buildpack version

The buildpack being used is defined in your deployment descriptor e.g. as part of the `manifest.yml` file via the
[buildpacks](https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#buildpack) attribute.

If it is set to `sap_java_buildpack` then the **newest** available version of the SAP Java buildpack is used.
Use command `cf buildpacks` to get the exact version of `sap_java_buildpack`:

```sh
buildpack                       position   enabled   locked   filename                                             stack
java_buildpack                  2          true      false    java_buildpack-cached-cflinuxfs3-v4.31.1.zip         cflinuxfs3
.
.
.
sap_java_buildpack              12         true      false    sap_java_buildpack-v1.26.1.zip
sap_java_buildpack_1_26         13         true      false    sap_java_buildpack-v1.26.1.zip
sap_java_buildpack_1_25         14         true      false    sap_java_buildpack-v1.25.0.zip
```

### Increase log level to `DEBUG`

You should also increase the logging level in your application. This can be done by setting the `SET_LOGGING_LEVEL`
environment variable for your application. You can do this in the `manifest.yml` with the `env` option like so:

```yaml
env:
    SET_LOGGING_LEVEL: '{com.sap.xs.security: DEBUG, com.sap.cloud.security: DEBUG}'
```

After you have made changes to the `manifest.yml` you need do re-deploy your app.
This sets the logging level for this library and the security parts of the buildpack to `DEBUG`.

For a running application this can also be done with the `cf` command line tool:

```shell
cf set-env <your app name> SET_LOGGING_LEVEL "{com.sap.xs.security: DEBUG, com.sap.cloud.security: DEBUG}"
```

You need to restage your application for the changes to take effect.


## [OPTIONAL] Leverage new API and features
You can continue [here](Migration_SAPJavaBuildpackProjects_V2.md) to understand what needs to be done to leverage the new `java-api` that is exposed by the SAP Java Buildpack as of version `1.26.1`.
