# Change Log 

All notable changes to this project will be documented in this file.
## 1.4.0
* API method to query [token validity](https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/spring-xsuaa/src/main/java/com/sap/cloud/security/xsuaa/token/Token.java#L167)
* Bugfix in basic authentication support: allow  usage of JWT token or basic authentication with one configuration
## 1.3.1
* Broker plan validation failed due to incorrect audience validation
## 1.3.0
* JwtGenerator offers enhancement options: custom claims and audience
* Test framework support for multi tenancy

## 1.2.0
* Eases enhancement of TokenAuthenticationConverter ([issue 23](https://github.com/SAP/cloud-security-xsuaa-integration/issues/23))
* Makes XsuaaAudienceValidator more robust ([issue 21](https://github.com/SAP/cloud-security-xsuaa-integration/issues/21))
* XSTokenRequest accepts custom RestTemplate ([issue 25](https://github.com/SAP/cloud-security-xsuaa-integration/issues/25))
* Provides spring-xsuaa-test library with JWTGenerator ([issue 29](https://github.com/SAP/cloud-security-xsuaa-integration/issues/29))
* Provides spring-xsuaa-mock library with XSUAA authentication mock web server for offline token key validation ([issue 30](https://github.com/SAP/cloud-security-xsuaa-integration/issues/30))


## 1.1.0

* Spring-Security 5 integration libraries. Added AudienceValidator
* Spring-Security 5 Support for basic authentication

## 1.1.0.RC1

* Initial version including spring-security 5 integration libraries


## 1.0.0

* Initial version of the api for SAP Java Buildpack

