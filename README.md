# Description
Authentication services provided by the xsuaa service on [SAP Cloud Platform](https://cloudplatform.sap.com) or [SAP HANA XS Advanced](https://help.sap.com/viewer/4505d0bdaf4948449b7f7379d24d0f0d/2.0.00/en-US) rely on usage of the OAuth 2.0 protocol and issued OAuth 2.0 access tokens.
Applications making use of the xsuaa service require libraries to validate access tokens issued by xsuaa.
## Java web applications using SAP Java Buildpack
The SAP Java Buildpack contains libraries for validating access tokens and application developers access the functions require the [api](./api). See [sap-java-builpack-api-uage](samples/sap-java-buildpack-api-usage) for an example.
# Requirements
## Java web applications using SAP Java Buildpack
Application using the SAP Java buildpack must configure XSUAA as authentication-methos in their web.xml.
```
<web-app>
<display-name>sample</display-name>
  <login-config> 
    <auth-method>XSUAA</auth-method> 
  </login-config> 
</web-app> 
```
In the Java coding, use the @ServletSecurity annotations:
```
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.*;
import javax.servlet.http.*;
/**
* Servlet implementation class HomeServlet
*/
@WebServlet(“/*”)
@ServletSecurity(@HttpConstraint(rolesAllowed = { “Display” }))
public class HomeServlet extends HttpServlet {
/**
* @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
*/
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
response.getWriter().println(“principal” + request.getUserPrincipal());
}
```
# Download and Installation
To download and install the this project clone this repository via:
```
git clone https://github.com/SAP/cloud-security-xsuaa-integration
```
For details on how to configure and run the the project please take a look into the README in the corresponding directory.

# Limitations
Libraries and information provided here is around the topic of integrating with the xsuaa service. General integration into other OAuth authorization servers is not the primary focus.

# How to obtain support
Licensed SAP customers can get support through [SAP Service Marketplace](https://support.sap.com)
# To-Do (upcoming changes)
The initial version will contain the api used by SAP Java Buildpack. Upcoming version will also provide integration into the Spring framework.

# License
Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file [LICENSE.md].
