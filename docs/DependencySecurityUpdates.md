<!-- SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency security updates on the 3.x line

The Spring baseline is Spring Boot **3.5.18**, Spring Framework **6.2.21** and
Spring Security **6.5.13**. These are Enterprise releases, not Maven Central
releases. Building or resolving artifacts that inherit this parent requires
an entitled repository or an organization-managed proxy that supplies them.
`provided` scope does not remove the need to resolve the parent's imported BOMs.

## Repository access

Use an existing organization-provided Maven `settings.xml` where available:

```sh
mvn -s /path/to/settings.xml -B verify
```

For direct Spring Enterprise access, obtain a registry token through your
subscription administrator. The official
[application-developer guide](https://techdocs.broadcom.com/us/en/truesource-software/platform/truesource-spring-enterprise/commercial/tse/guide-artifact-repository-developers.html)
documents both required repositories:

- `https://packages.broadcom.com/artifactory/spring-enterprise/`
- `https://packages.broadcom.com/artifactory/tanzu-spring-dependencies/`

Keep credentials in Maven settings or environment-backed server entries, never
in this repository. If using a mirror, its server ID and repository coverage
must also be configured correctly. Repository access alone is not evidence of
license entitlement or permission to redistribute the Enterprise artifacts.

## Additional security alignment

The parent overrides older Boot BOM defaults without adding unused artifacts
to any module's runtime dependencies:

| Family | Version |
| --- | --- |
| ActiveMQ Classic | 6.2.10 |
| Artemis, including its old-group relocation coordinates | 2.54.0 |
| Apache HttpCore 5 | 5.4.4 |
| Commons Lang | 3.20.0 |
| Hazelcast | 5.7.0 |
| MariaDB JDBC / R2DBC | 3.5.11 / 1.4.2 |
| RabbitMQ Java client | 5.38.0 |
| OpenTelemetry | 1.67.0 |
| Log4j / Logback | 2.26.1 / 1.6.6 |
| Embedded Tomcat | 10.1.62 |
| Bouncy Castle test-helper dependencies | jdk18on 1.87 |

Family BOMs are imported before Boot; explicit management is used for families
without a suitable BOM. The JWT test helper retains its existing API, excludes
the discontinued Bouncy Castle `jdk15on` artifacts and supplies the patched
`jdk18on` artifacts instead.

The Boot update also supplies patched Jackson 2.21.7, Netty 4.1.139.Final,
PostgreSQL 42.7.14, FreeMarker 2.3.35 and Undertow 2.3.26.Final.

## Deliberately unresolved items

- **Derby / CVE-2022-46337:** 10.17.1.0 is published but requires Java 21. This
  project still supports Java 17; the 10.16 fix is not published on Central.
- **Infinispan CLI / CVE-2025-5731:** no fixed release in the existing 15.x line
  was identified. Moving to 16.x would violate the no-major-upgrade constraint.
- **Querydsl / CVE-2024-49203:** the original `com.querydsl` coordinates have no
  fixed release beyond 5.1.0. A fork migration is not a version-only update.
- **CVE-2026-3260:** officially rejected by the CNA; it is not an upgrade target
  even if a scanner still reports it for Undertow.
- **Tomcat / CVE-2026-133325:** 10.1.62 has a TLS-PSK/TLS 1.3 cluster issue; the
  manufacturer recommends TLS 1.2 until 10.1.63 is available. A dependency bump
  alone cannot currently remove this finding.

These statements concern dependency metadata, not application-specific
exploitability. A WAR's buildpack/container Tomcat must be assessed separately.

## Dependabot review

The compatible updates from **#2071** are incorporated: Jetty, Reactor,
Caffeine, Surefire, JaCoCo, the Central publishing plugin and Logback.
The Maven Central publishing plugin is upgraded in both publishing POMs.
No major-version update is included.

## Verification snapshot (2026-11-26)

- Java 17 Maven reactor build: **1,014 tests, zero failures/errors, three skips**.
- All Spring generations and resolved Bouncy Castle test-helper artifacts were
  checked; the old `jdk15on` artifacts are absent.
- No major-version increase was found in the effective dependency management.
- The effective-POM OSV comparison went from **108 advisory IDs to three**;
  the Spring manufacturer comparison went from **115 CVEs to zero**. The three
  remaining IDs are the Derby, Querydsl and Infinispan constraints listed above.

These counts include unused dependency-management entries. They are not a
runtime exploitability assessment or a binary scan of shaded JARs/buildpacks.

## Full workflow build snapshot (2026-11-27)

All **11 Maven steps** from the workflow pass locally with Java 17 and
Enterprise-enabled settings, without CLI skip flags: the reactor `install`,
both integration-test projects and all eight samples. This executes **1,097
tests with zero failures/errors and three skips**, including Javadoc and the
configured analysis goals.

The hybrid sample had an unavailable Jakarta logging dependency, 3.7.3. Its
pin is corrected to the published **3.8.6** release within the same major line.

GitHub-hosted builds still need separate Enterprise repository configuration;
the local organization's Maven settings are not present on those runners.
Adding credentials alone is not sufficient: the workflow must generate Maven
settings for both Maven and CodeQL. The existing branch filters also omit
`main-3.x`. These workflow changes require a CI-access decision and are not
included in the sample dependency fix.
