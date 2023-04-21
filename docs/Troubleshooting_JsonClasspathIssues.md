# Troubleshooting JSON classpath issues

We have observed different issues when using this library in conjunction with libraries that bring in 
their own json dependencies. This guide will help you identify the root cause of the issue and shows you how to solve them.

First you should be aware of your application's dependencies. Take a look at [Analyze dependencies](#Analyze-dependencies) for more information.

From our experience there are two different root causes for json classpath issues:

  1. Your application brings in a too old version of `org.json`
  2. Your application brings in another json library that conflicts with `org.json`

To identify how your application is affected, you have to take a look at your error logs, e.g. with `cf logs`.
If you find messages like:
`java.lang.NoSuchMethodError: org.json.JSONArray.forEach`
or
`java.lang.NoSuchMethodError: org.json.JSONObject.isEmpty`
you are most likely using an too old version of `org.json`, see section [Old json version](#Old-json-version) for more information.
If you have linkage errors complaining about duplicated definitions, please take a look at [Conflicting library](#Conflicting-library).

## Analyze dependencies

The json classpath issues are most likely caused by incompatible json dependencies. To analyze the dependencies
of your application, you can use the maven  [dependency plugin](http://maven.apache.org/plugins/maven-dependency-plugin/usage.html#dependency:tree).
It allows you to print the effective dependencies of your application. You can execute the plugin via the command line from
the directory where your `pom.xml` file is stored with `mvn dependency:tree`.
This will generate an output like this:

```log
❯ mvn dependency:tree
[INFO] Scanning for projects...
[INFO]
[INFO] --< com.sap.cloud.security.xssec.samples:sap-java-buildpack-api-usage >--
[INFO] Building sap-java-buildpack-api-usage 2.7.1
[INFO] --------------------------------[ war ]---------------------------------
[INFO]
[INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ sap-java-buildpack-api-usage ---
[INFO] com.sap.cloud.security.xssec.samples:sap-java-buildpack-api-usage:war:2.7.1
[INFO] +- com.sap.cloud.security.xsuaa:api:jar:2.7.1:provided
[INFO] +- javax.servlet:javax.servlet-api:jar:3.0.1:provided
[INFO] \- com.sap.cloud.security:java-security:jar:2.7.1:compile
[INFO]    +- com.sap.cloud.security:java-api:jar:2.7.1:compile
[INFO]    |  \- com.google.code.findbugs:jsr305:jar:3.0.2:compile
[INFO]    +- commons-io:commons-io:jar:2.6:compile
[INFO]    \- com.sap.cloud.security.xsuaa:token-client:jar:2.7.1:compile
[INFO]       +- org.json:json:jar:20190722:compile
[INFO]       \- com.github.ben-manes.caffeine:caffeine:jar:2.8.2:compile
[INFO]          +- org.checkerframework:checker-qual:jar:3.3.0:compile
[INFO]          \- com.google.errorprone:error_prone_annotations:jar:2.3.4:compile
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  0.694 s
[INFO] Finished at: 2020-06-08T11:19:27+02:00
[INFO] ------------------------------------------------------------------------
```

Here you see that `com.sap.cloud.security:java-security` brings in `org.json:json` with version `20190722`.
If you search for 'json' you might find other libraries that also bring in `org.json` or other json libraries.

## Old json version

Before you proceeded, make sure you know how to create the dependency tree of your application described [here](#Analyze-dependencies).

Search for 'json' in your dependency tree. You will find the json libraries your application depends upon. 
If the found version of `org.json:json` is lower than `20190722`, you probably have another dependency that also brings
in `org.json:json` but with a lower version!
This is problematic because this library makes use of features that are not available in the older version of `org.json:json`.
To avoid this issue you can exclude `org.json:json` from the other dependency that includes it or you can declare the dependency
to org.json in your application explicitly. 

### Exclude org.json dependency

You have identified another dependency that brings in an older version of `org.json`.
Lets call this dependency `example.org:some-lib`. First you might want to check 
if there is a newer version of `some-lib` that also includes a newer version of
`org.json` (at least `20190722`). In this case you could just update `some-lib`
and the issue is resolved!
If there is no newer version of `some-lib` or it cannot be used for some reason, you can
declare an exclusion rule for `org.json` on `some-lib` like this:

```xml
<dependency>
  <groupId>org.example</groupId>
  <artifactId>some-lib</artifactId>
  <version>1.0</version>
  <exclusions>
    <exclusion>
      <groupId>org.json</groupId>
      <artifactId>json</artifactId>
    </exclusion>
  </exclusions>
</dependency>
```

> Note that this will not forbid `some-lib` from using `org.json`. It just lets maven ignore the `org.json` dependency declaration of `some-lib` and will therefore use the `org.json` version declared in this security library.

Please test if your application still works correctly after defining this exclusion rule!

### Declare dependency to org.json

You can explicitly define a dependency to `org.json:json` in your application's `pom.xml`:

```xml
<dependency>
  <groupId>org.json</groupId>
  <artifactId>json</artifactId>
  <version>20190722</version>
</dependency>
```

This will force maven to use this version of `org.json:json` instead of the one the dependencies bring in.

> Make sure to test your application thoroughly after declaring this dependency!

## Conflicting library

This library requires [org.json](https://github.com/stleary/JSON-java). Unfortunately,
there are other json libraries with different names that contain the exact the same classes in the same packages 
like `org.json`. This can lead to linkage errors complaining about duplicated class definitions.

Libraries we have observed that caused those issues are:

- [com.vaadin.external.google:android-json](https://mvnrepository.com/artifact/com.vaadin.external.google/android-json)
  - Dependency of [spring boot test starter](https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-test/)
- [com.unboundid.components:json](https://mvnrepository.com/artifact/com.unboundid.components/json/1.0.0)

To analyze if your application contains one these libraries you can create the dependency tree of your application.
You can learn how to do this [here](#Analyze-dependencies).

If your application contains a conflicting library, you can try to exclude it to get rid of the error message.
Likewise you can exclude json.org from this security library. This is described [here](#exclude-orgjson-dependency).

> Please test if your application still works correctly after defining an exclusion rule!
