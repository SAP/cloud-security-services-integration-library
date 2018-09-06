# Description
Authentication services provided by the xsuaa service on [SAP Cloud Platform](https://cloudplatform.sap.com) or [SAP HANA XS Advanced](https://help.sap.com/viewer/4505d0bdaf4948449b7f7379d24d0f0d/2.0.00/en-US) rely on usage of the [OAuth 2.0](https://oauth.net) protocol and OAuth 2.0 access tokens.
When integrating authentication with xsuaa in an application like a Java web application, libraries for validating access tokens are required.
## Java web applications using SAP Java Buildpack
The SAP Java Buildpack contains libraries for validating access tokens and application developers access the functions require the [api](./api). See [sap-java-builpack-api-uage](samples/sap-java-buildpack-api-usage) for an example.
# Requirements
## Java web applications using SAP Java Buildpack
- Java 8
- maven 3.3.9 or later

# Download and Installation
To download and install the this project clone this repository via:
```
git clone ##
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
