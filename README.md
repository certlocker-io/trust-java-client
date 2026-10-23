<img align="right" alt="Certlocker" src="https://certlocker.io/Images/logo-white-32.png" width="32" height="32">

# Trust Java Client
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This Trust client communicates with [Certlocker Trust](https://trust.certlocker.io) and
allows you to read secrets, certificates and tokens.

Requires Java 21.

## Build configuration
You can integrate this library into your project by defining it as a __Maven__ or __Gradle__ dependency.

The current version is **1.0.1**.

**Maven**
```xml
<dependency>
    <groupId>io.certlocker</groupId>
    <artifactId>trust-java-client</artifactId>
    <version>1.0.1</version>
</dependency>
```

**Gradle DSL**
```groovy
dependencies {
    implementation 'io.certlocker:trust-java-client:1.0.1'
}
```

Jackson Databind 3.2.3 (`tools.jackson.core:jackson-databind`) is brought in with the client.

## Features
`get` returns data regarding the asset. `fetch` returns the contents of the asset.

- Secrets
  - Get the secret
  - Fetch the secret contents
  - Read a secret as PEM, configuration, password, credentials or a private key
- Certificates
  - Get the certificate
  - Fetch the certificate
  - Fetch the certificate bundle
- Tokens
  - Get the token

## Getting started
First, create the client with the Trust URL and an API key.

```java
final String API_KEY = "YOUR_API_KEY";
final TrustClient client = TrustClient.builder()
        .apiKey(API_KEY)
        .url("https://trust.certlocker.io")
        .build();
```

After that you can create the TrustService:

```java
final TrustService service = new TrustService(client);
```

After that, for example you can read secrets:

```java
try (TrustService service = new TrustService(TrustClient.builder()
        .apiKey("YOUR_API_KEY")
        .url("https://trust.certlocker.io"))) {
    Secret secret = service.getSecret("mvusgvkv5");
    System.out.println(secret);
    Configuration configuration = service.getSecretAsConfiguration("mvusgvkv5");
    System.out.println(configuration);
    Pem pem = service.getSecretAsPem("b5fqj6c8d");
    System.out.println(pem);
    Password password = service.getSecretAsPassword("v5q7pspif");
    System.out.println(password);
    Credentials cred = service.getSecretAsCredentials("17bu1p62uq");
    System.out.println(cred);
    PrivateKey privateKey = service.getSecretAsPrivateKey("k8m7c8pps");
    System.out.println(privateKey);
} catch (TrustClientException ex) {
    System.err.println(ex.getMessage());
}
```

`TrustService` closes the underlying client when it is closed.

## HTTP client
The builder accepts the same settings as `HttpClient.Builder`, so the connection and the HTTP client are configured in one chain. When no HTTP settings are supplied, the client uses a connect timeout of 10 seconds.

```java
final TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .apiKey(API_KEY)
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .version(HttpClient.Version.HTTP_1_1)
        .build();
```

An existing JDK builder can be passed in instead. This replaces any HTTP settings already applied, so call it before the other HTTP methods when combining both.

```java
final TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .apiKey(API_KEY)
        .httpClientBuilder(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL))
        .build();
```

The same builder also accepts `cookieHandler`, `sslContext`, `sslParameters`, `executor`, `priority`, `proxy`, `authenticator` and `localAddress`.

## License
Licensed under GNU General Public License v3.0. See the [LICENSE](trust-java-client/LICENSE) file for details.
