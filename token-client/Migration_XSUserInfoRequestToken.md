# Migration guide for applications that perform token flows using (XS)UserInfo

This guide is for you if your application is requesting tokens using `requestToken`, `requestTokenForUser` or
`requestTokenForClient` from `(XS)UserInfo`. **Those methods are being deprecated.** The new way to perform token flows is
by using the [token-client](/token-client) library. This step-by-step guide explains how to migrate to this library.


## Prerequisite

Make sure you have a dependency to `token-client` defined in your `pom.xml` like described
[here](/token-client#configuration-for-javaspring-applications) if you are using Spring or
[here](/token-client#configuration-for-java-applications) if you are not using Spring.

## Use the new token-client library

Before you can use the new token-client library you first have to understand what token flows you
are currently executing in your application.

With `(XS)UserInfo` you can only execute **client credentials** and **user token** flows.  If you
are using the `requestTokenForUser` method, a user token flow is executed.  If you are using
`requestTokenForClient`, a client credentials flow is performed.  With the `requestToken` method
either an user token or a client credentials token flow can be performed! In this case you have to
check the `XSTokenRequest` object's `type` attribute to see if you need to replace this call with an
user token flow or a client credentials flow!

You can proceed to the respective section for more information on how to perform client credentials or user token flows.

### Perform a client credentials flow

See the documentation [here](/token-client#client-credentials-token-flow) to perform a client
credentials flow using the token-client library.
Make sure you pass `clientId`, `clientSecret` and the `uaaUrl` to the flow.

### Perform a user token flow

See the documentation [here](/token-client#user-token-flow) to perform a user token flow
using the token-client library.

Note that the user token flow is an exchange flow. This means that you *exchange* your user token
for an access token.  When using `requestToken` or `requestTokenForUser` from `(XS)UserInfo` you did
not have to pass a token. The `(XS)UserInfo` object already has the token information and
automatically uses it for the request. Using the `token-client` library this is different! It is
decoupled from the token itself. That is why you have to pass it via the `token` method. You can
obtain the token if you are using the new API with `getTokenValue()` or, if you are using
`(XS)UserInfo`, you can obtain it via `getAppToken()`.

Make also sure you pass `clientId`, `clientSecret` and the `uaaUrl` to the flow!

## Samples
- Token client used in java application: [Java sample](/samples/java-tokenclient-usage)
- Token-client used in spring boot application: [Spring Boot sample](/samples/spring-security-xsuaa-usage)

