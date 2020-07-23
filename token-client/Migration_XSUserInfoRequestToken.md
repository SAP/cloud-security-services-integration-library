# Migration guide for applications that perform token flows using (XS)UserInfo

This guide is for you if your application is requesting tokens using `requestToken`, `requestTokenForUser` or
`requestTokenForClient` from `(XS)UserInfo`. **Those methods are being deprecated.** The new way to perform token flows is
by using the [token-client](/token-client) library. This step-by-step guide explains how to migrate to this library.


## Prerequisite

Make sure you have a dependency to `token-client` defined in your `pom.xml` like described
[here](/token-client#configuration-for-javaspring-applications) if you are using Spring or
[here](/token-client#configuration-for-java-applications) if you are not using Spring.

## Use token-client

With `(XS)UserInfo` you can perform **Client Credentials** and **User Token** flows by using the following methods:

  - **User Token** via `requestTokenForUser` method. Needs to be replaced with a user token flow [described here](/token-client#user-token-flow).
  - **Client Credentials** via `requestTokenForClient` method.  Needs to be replaced with a client credentials token flow [described here](/token-client#client-credentials-token-flow).
  - **User Token** or **Client Credentials** via  `requestToken`. Here you have to check how you have configured the `XSTokenRequest` object and perform a user token flow or a client credentials flow.

General instructions and more information can be found in the [token-client documentation](/token-client).

Note that the user token flow is an exchange flow. This means that you *exchange* your user token for an access token.
When using `requestToken` or `requestTokenForUser` you did not have to pass a token. The `UserInfo` object already has
the token information and automatically uses it for the request. Using the `token-client` library this is different! It
is decoupled from the token itself. That is why you have to pass it via the `token` method. You can obtain the token if
you are using the new API with `getTokenValue()` or, if you are using `(XS)UserInfo`, you can obtain it via
`getAppToken()`.

## Samples
- Token client used in java application: [Java sample](/samples/java-tokenclient-usage)
- Token-client used in spring boot application: [Spring Boot sample](/samples/spring-security-xsuaa-usage)

