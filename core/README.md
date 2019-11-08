# Java Security Library

A Java implementation of JSON Web Token (JWT) - RFC 7519.

## Configuration

### Maven Dependencies
```xml
<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>core</artifactId>
    <version>2.3.0</version>
</dependency>
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
    <version>2.3.0</version>
</dependency>

```
## Usage

### Validate Access Token

```java
CombiningValidator combiningValidator =
      builderFor(ScpEnvironment.getXsuaaServiceConfiguration("CF")).build();
ValidationResult result = combiningValidator.validate(token);
if(!result.isValid()) {
   LOGGER.error("User is not authenticated: " + result.getErrorDescription());
}

```

### Get Access Token from SecurityContext
