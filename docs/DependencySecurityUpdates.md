<!-- SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency security updates and Spring Boot 3 compatibility

The normal modules use the aligned Spring Boot **4.1.3**, Spring Framework
**7.0.11** and Spring Security **7.1.3** baseline. The Spring Boot 3 modules
(`spring-security-3`, `spring-security-3-starter` and `token-client-spring-3`)
use Spring Boot **3.5.18**, Framework **6.2.21**, Security **6.5.13** and
Reactor **3.8.8** through the shared `legacy3.*` properties.

Both OAuth2 and Security versions stay on 6.x in the compatibility modules.
The token-client compatibility module also overrides the Boot/Security BOM
properties, not just four Framework artifact versions, to avoid a mixed
Spring 6 / Spring 7 dependency graph.

## Enterprise repository access

The Spring Boot 3 baseline is Enterprise-only. The compatibility artifacts
require an entitled Spring Enterprise repository or an organization-managed
proxy. The normal Boot 4 baseline remains available on Maven Central.

Use the organization-provided settings file when available:

```sh
mvn -s /path/to/settings.xml -B verify
```

For direct access, the subscription administrator must provide a registry token.
Follow the official
[application-developer guide](https://techdocs.broadcom.com/us/en/truesource-software/platform/truesource-spring-enterprise/commercial/tse/guide-artifact-repository-developers.html)
and configure both `spring-enterprise` and `tanzu-spring-dependencies` repositories.
Keep credentials in Maven settings or environment-backed server entries, not
in the POM or source control. Confirm license/redistribution requirements before
publishing or distributing artifacts that rely on this Enterprise baseline.

## Security overrides

Shared dependency management upgrades vulnerable families, including when the
compatibility modules import the older Boot 3 BOM:

| Family | Version |
| --- | --- |
| ActiveMQ Classic / Artemis | 6.2.10 / 2.54.0 |
| Apache HttpClient 5 / HttpCore 5 | 5.6.5 / 5.4.4 |
| Commons Lang / Hazelcast | 3.20.0 / 5.7.0 |
| MariaDB JDBC / R2DBC | 3.5.11 / 1.4.2 |
| RabbitMQ Java client | 5.38.0 |
| OpenTelemetry | 1.67.0 |
| Log4j / Logback | 2.26.1 / 1.6.6 |
| Embedded Tomcat, Boot 3 / Boot 4 | 10.1.62 / 11.0.27 |

These are management overrides, not new runtime dependencies. Family BOMs
precede the Boot import. MySQL remains on its existing 9.7.0 major rather than
silently adopting Boot's newer 26.x calendar-version line.

## Remaining constraints

- Derby's published CVE-2022-46337 fix requires Java 21; Java 17 remains supported.
- The original Querydsl 5.1.0 coordinates have no identified fixed minor release.
- The Boot 3 Infinispan CLI finding has no identified fixed 15.x release; 16.x is
  not introduced into those modules.
- Undertow CVE-2026-3260 is officially rejected, not an upgrade target.
- Tomcat's TLS-PSK/TLS 1.3 cluster issue requires a configuration workaround
  until the next patched release; a WAR's container Tomcat is controlled by
  its buildpack, not by these dependency declarations.

## Dependabot review

- **#2074:** the compatible Jetty update is incorporated. Its Boot 4.2 / Framework
  7.1 / Security 7.2 / Reactor 3.9 stack also changes unrelated transitive majors;
  the coherent patched 4.1 stack is retained instead.
- **#2072:** its Framework-only 7.1 update is not mixed with the Boot 4.1 baseline.
  Framework 7.0.11 contains the current fixes for this stack.
- **#2073:** rejected as written: it changes the Boot 3 modules' OAuth2 property
  from the 6.x baseline to 7.2.0. Both compatibility modules retain the shared
  6.5.13 property. Major Spring updates are ignored to prevent recurrence.

The review incorporates or explains every open Maven Dependabot PR for this
branch. It does not merge or close the remote PRs.

## Verification snapshot (2026-11-26)

- Java 17 Maven reactor build: **1,242 tests, zero failures/errors, two skips**,
  including the Spring Boot 3 compatibility modules.
- Explicit old Logback test pins were replaced with the central property to
  avoid mixing incompatible Classic/Core releases.
- No major-version increase was found in the effective dependency management;
  the previously mixed token-client compatibility BOM is corrected to Boot 3.
- The effective-POM OSV comparison went from **110 advisory IDs to three**;
  the Spring manufacturer comparison went from **121 CVEs to zero**. The three
  remaining IDs are the Derby, Querydsl and Infinispan constraints listed above.

These counts include unused dependency-management entries. They are not a
runtime exploitability assessment or a binary scan of shaded JARs/buildpacks.
