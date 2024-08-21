---
name: How to get Support
about: Learn how to get support via SAP official channels
title: "--- DO NOT CREATE THIS ISSUE ---"
labels: invalid
assignees: ''

---

**Support is no longer provided via the Issues feature in this Github repository.**

Please use SAP official support channels to get support under component BC-CP-CF-SEC-LIB or Security Client Libraries.

Before opening support tickets, please check the Troubleshooting and Common Pitfalls sections first in addition to the READMEs of the modules that you are using from this repository.

Make sure to include the following mandatory information to get a response:

- List of module(s) of this library used by your application (java-security, spring-security, spring-xsuaa etc...) and version of this library installed in your application.\
*Alternative*: maven dependency tree
- Auth service set-up of your application (XSUAA, IAS, XSUAA+IAS, IAS+AMS, etc.)
- For exceptions: Stack trace that includes the executed code locations of this library that lead to the exception
- For unexpected 401 / 403 response codes: relevant log output of this library with active DEBUG flag (see module READMEs for a guide how to enable it)
- Steps you have tried to fix the problem
- Reason why you believe a bug in this library is causing your problem

Unfortunately, we can **NOT** offer consulting via support channels.
