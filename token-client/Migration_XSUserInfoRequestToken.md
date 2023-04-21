# Migration guide for applications that perform token flows using (XS)UserInfo

This guide is for you if your application is requesting tokens using `requestToken`, `requestTokenForUser` or
`requestTokenForClient` from `(XS)UserInfo`. **Those methods are being deprecated.** The new way to perform token flows is
by using the [token-client](/token-client) library. This step-by-step guide explains how to migrate to this library.


## Prerequisite

Make sure you have a dependency to `token-client` defined in your `pom.xml` like described
[here](README.md#11-configuration-for-spring-applications) if you are using Spring or
[here](README.md#12-configuration-for-java-ee-applications) if you are not using Spring.

## Use the new token-client library

Before you can use the new token-client library you first have to understand what token flows you
are currently executing in your application.

### 1. Understand your application

With `(XS)UserInfo` you can only execute **client credentials** and **user token** flows.  If you
are using the `requestTokenForUser` method, a user token flow is executed.  If you are using
`requestTokenForClient`, a client credentials flow is performed.  With the `requestToken` method
either an user token or a client credentials token flow can be performed! In this case you have to
check the `XSTokenRequest` object's `type` attribute to see if you need to replace this call with an
user token flow or a client credentials flow!


### 2. Create an XsuaaTokenFlows object

Before you can perform a specific token flow, you first have to create an `XsuaaTokenFlows` object.
To create this object you have to pass in the following data: `clientId`, `clientSecret` and
the `uaaUrl`. How you would create the `XsuaaTokenFlows` depends on the type of your application.
If you are using spring see [here](README.md#xsuaatokenflows-initialization) if not see [here](README.md#xsuaatokenflows-initialization-1).


### 3. Perform the flow

Now you are ready to perform the specific flow!

If you want to perform a client credentials flow  see the documentation [here](README.md#client-credentials-token-flow)

If you want to perform a jwt bearer token flow see the documentation [here](README.md#jwt-bearer-token-flow).

Note that the user token flow is an exchange flow. This means that you *exchange* your user token
for an access token.  When using `requestToken` or `requestTokenForUser` from `(XS)UserInfo` you did
not have to pass a token. The `(XS)UserInfo` object already has the token information and
automatically uses it for the request. Using the `token-client` library this is different! It is
decoupled from the token itself. That is why you have to pass it via the `token` method. You can
obtain the token if you are using the new API with `getTokenValue()` or, if you are using
`(XS)UserInfo`, you can obtain it via `getAppToken()`.

## Samples
- Token client used in java application: [Java sample](/samples/java-tokenclient-usage)
- Token-client used in spring boot application: [Spring Boot sample](/samples/spring-security-xsuaa-usage)
