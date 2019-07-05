# Descritpion
This is a java Springboot application using the `spring-webflux` as the web framework and protected by the `spring-security-oauth2-resource-server` and the `cloud-security-xsuaa-integration`.

This application exposes the security information through a REST API.
* `/v1/demo`: Produces Http response with content-type `application/json; UTF-8` and the body containing the zone id of the JWT or an error message; 
