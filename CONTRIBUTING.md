# Contributing to cloud-security-services-integration-library

If you want to contribute to cloud-security-services-integration-library you're more than Welcome! Please read this document to understand what you can do:
 * [Analyze Issues](#analyze-issues)
 * [Report an Issue](#report-an-issue)
 * [Contribute Code](#contribute-code)

## Analyze Issues

Analyzing issues can be a lot of effort. Any help is appreciated!
Go to [the GitHub issue tracker](https://github.com/SAP/cloud-security-services-integration-library/issues?state=open) and find an open issue which needs additional work or a bugfix.

Additional work may be: further information, or it might be a hint that helps understand the issue. Maybe you can even find and [contribute](#contribute-code) a bugfix?


## Report an Issue

If you find a bug in cloud-security-services-integration-library code feel free to report it.
To avoid back and forth messages and shorten the bug fix time provide a well-described issue description. Please follow the [checklist](#Issue-Report-Checklist) below.

Once you have familiarized with the checklist, you can go to the [GitHub issue tracker](https://github.com/SAP/cloud-security-services-integration-library/issues/new/choose) to report the issue.

> For consultation questions search first in [GitHub Consultation Questions](https://github.com/SAP/cloud-security-services-integration-library/issues?q=label%3Aconsultation+) for already replied questions. If you still don't find an answer create a [new issue](https://github.com/SAP/cloud-security-services-integration-library/issues/new?assignees=&labels=consultation&template=consultation-question.md&title=).

### Issue Report Checklist

 * Real, current bug
 * Not a duplicate
 * Not covered in "Common Pitfalls" section of corresponding module's README.md e.g. [java-security#common-pitfalls](/java-security/README.md#common-pitfalls)
 * Reproducible
 * Good summary
 * Well-documented
    * log level increased to `DEBUG` debug logs provided
    * POM provided
    * dependency tree provided
    * code snippet provided


### Requirements for an Issue report

These seven requirements are mandatory for a good Issue report:
1. **Only real bugs**: make sure to only report real bugs! Do not report:
   * issues caused by application code or any code outside cloud-security-services-integration-library library.
   * something you do not get to work properly. Use a support channels mentioned above to request help.
2. No duplicate: you have searched the issue tracker to make sure the bug has not yet been reported
3. Good summary: the summary should be specific to the issue
4. Current bug: the bug can be reproduced in the most current version (Deprecated modules, classes, methods etc. are not supported)
5. Reproducible bug: there are clear steps to reproduce the issue. 
6. Precise description:
   * precisely state the expected and the actual behavior
   * check troubleshoot guidelines for [Java applications](./java-security/README.md#troubleshooting) 
   * check troubleshoot guidelines for [Spring applications](./spring-security/README.md#troubleshooting)  
7. Only one bug per report: open different tickets for different issues

Please report bugs in English, so all users can understand them.


## Contribute Code

You are welcome to contribute code to cloud-security-services-integration-library in order to fix bugs or to implement new features.

There are two important things to know:

1.  You must be aware of the Apache License (which describes contributions) and **agree to the Developer Certificate of Origin**. This is common practice in all major Open Source projects. To make this process as simple as possible, we are using *[CLA assistant](https://cla-assistant.io/)*. CLA assistant is an open source tool that integrates with GitHub very well and enables a one-click-experience for accepting the DCO. See the respective section below for details.
2.  There are **several requirements regarding code style, quality, and product standards** that need to be adhered to. The [Contribution Content Guidelines](#Contribution-Content-Guidelines) section below describes that in more details.


### Developer Certificate of Origin (DCO)

Due to legal reasons, contributors will be asked to accept a DCO before they submit the first pull request to this project. SAP uses [the standard DCO text of the Linux Foundation](https://developercertificate.org/).  
This happens in an automated fashion during the submission process: the CLA assistant tool will add a comment to the pull request. Click it to check the DCO, then accept it on the following screen. CLA assistant will save this decision for upcoming contributions.

This DCO replaces the previously used CLA ("Contributor License Agreement") as well as the "Corporate Contributor License Agreement" with new terms which are well-known standards and hence easier to approve by legal departments. Contributors who had already accepted the CLA in the past may be asked once to accept the new DCO.


### Contribution Content Guidelines

Contributed content can be accepted if it:

1. is useful to improve cloud-security-services-integration-library library (explained above)
2. follows the applicable guidelines and standards

Some of the most important rules are listed below:

-   Follow a clean coding style principles that complies with JAVA naming convention
-   Apply maven formatter goal `mvn formatter:format` when you're ready to push your code
-   Provide full test coverage for your implementation
-   Comment your code where it gets non-trivial and keep the JavaDocs up to date
-   Use the most restrictive access level possible for any given member
-   **Do NOT** do any incompatible changes

### How to contribute - the Process

1. Make sure the change is useful (e.g. a bugfix or a useful feature). Recommended way is to propose it in a GitHub issue
2. Create a branch forking the cloud-security-services-integration-library repository and implement your change
3. Commit and push your changes to that branch
    -   If you have several commits, squash them into one (see [this explanation](http://davidwalsh.name/squash-commits-git))
4. If your change fixes an issue reported at GitHub, add the following line to the commit message:
    - ```Fixes https://github.com/SAP/cloud-security-services-integration-library/issues/(issueNumber)```
    - Do NOT add a colon after "Fixes" - this prevents automatic closing.
    - When your pull request number is known (e.g. because you enhance a pull request after a code review), you can also add the line ```Closes https://github.com/SAP/cloud-security-services-integration-library/issues/pull/(pullRequestNumber)```
5. Create a Pull Request to https://github.com/SAP/cloud-security-services-integration-library/pulls
6. Follow the link posted by the CLA assistant to your pull request and accept the Developer Certificate of Origin, as described in detail above.
7. Wait for our code review and approval, possibly enhancing your change on request
8. Once the change has been approved it will be merged into main and pull request will be closed (feel free to delete the now obsolete branch)