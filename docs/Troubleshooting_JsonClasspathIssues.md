# Troubleshooting JSON classpath issues

This library has a dependency to the [JSON-Java](https://github.com/stleary/JSON-java) library.
There are other libraries out there that define the same classes and can cause classpath issues when used in conjunction
with this security library. Typical issues are `NoSuchMethod`, `ClassNotFound`
or linkage error complaining about duplicate class definitions.

Libraries we have observed that can cause those issues:

- [JsonPath](https://github.com/json-path/JsonPath)
  - Dependency of [spring boot test starter](https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-test/)
- [com.unboundid.components:json](https://mvnrepository.com/artifact/com.unboundid.components/json/1.0.0)

## Solving this Problem

You can solve this problem by either excluding JSON-Java from our library, by excluding the conflicting library from the
other dependency or by your application migrating to JSON-Java.

### Excluding JSON-Java

To exclude JSON-Java you have to define an exclusion rule at the location where
you include this library. So for example if you use java-security in your
application, you will need to add an exclusion block to the place where the
dependency is defined like so:

```xml
<dependency>
    <groupId>com.sap.cloud.security</groupId>
    <artifactId>java-security</artifactId>
    <exclusions>
        <exclusion>
        <groupId>org.json</groupId>
        <artifactId>json</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```

### Excluding the other JSON library

You can also exclude the other conflicting library the same way you would
exclude JSON-Java from java-security like described above. If you are not sure which dependency
brings in the conflicting library you can use maven with the
[dependency plugin](http://maven.apache.org/plugins/maven-dependency-plugin/usage.html#dependency:tree) and take a look
at the dependency tree.

### Migrate to JSON-Java

If you use the conflicting JSON library in your application you could replace it with
[JSON-Java](https://github.com/stleary/JSON-java).
Because most libraries that cause issues are based on an older
version of JSON-Java you might not need to change any code in your application.