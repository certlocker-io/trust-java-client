<img align="right" alt="Certlocker" src="https://certlocker.io/logo-white-32.png" width="32" height="32">

# Trust Java Client
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Java client for [Certlocker Trust](https://trust.certlocker.io): read secrets, certificates, and tokens over the Gateway API.

Requires **Java 21**.

## Dependency

Public coordinate: **`io.certlocker:trust-client:1.0.5`** (see `trustClientVersion` in `gradle.properties`).

**Maven**
```xml
<dependency>
    <groupId>io.certlocker</groupId>
    <artifactId>trust-client</artifactId>
    <version>1.0.5</version>
</dependency>
```

**Gradle**
```groovy
dependencies {
    implementation 'io.certlocker:trust-client:1.0.5'
}
```

Transitive: Jackson Databind via `tools.jackson:jackson-bom:3.2.4`, plus `jose4j` for Device OIDC JWT minting.

## Features

`get` returns asset metadata. `fetch` returns asset contents.

- **Secrets** — get / fetch; typed readers for PEM, configuration, password, credentials, private key
- **Certificates** — get / fetch / fetch bundle
- **Tokens** — get
- **Auth** — UI-minted static API token; ambient OIDC (GitHub Actions, GCP, Azure, Azure DevOps); Device OIDC; optional mint type `SECRET` / `CERTIFICATE` / `MCP`; 2FA `AuthCodePrompt`
- **Paths** — Gateway calls include `{accountId}`; path account must match the token’s account

## Authentication

Prefer federated OIDC for CI and machines. Use a UI-minted SECRET token for break-glass / local human use.

Audience for GitHub, GCP, Azure, and Device OIDC is per-account:

`https://trust.certlocker.io/oidc/<accountId>`

Azure DevOps uses ADO’s fixed audience `api://AzureADTokenExchange`; Trust matches the principal by issuer / `sub`, not the Trust audience URL.

### Static API token (UI-minted)

```java
TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .accountId("<accountId>")
        .apiToken("<ui-minted-token-id>")
        .build();
```

Gateway asset paths include the account, e.g. `/rest/api/v1/secret/{accountId}/fetch`. The path `accountId` must match the token’s account.

### Ambient OIDC (CI / cloud)

`fromAmbientOidc` / `preferAmbientOidc(true)` picks the first available ambient provider: GitHub Actions → GCP → Azure → Azure DevOps. `accountId` is taken from the exchange response when not set on the builder.

```java
TrustClient client = TrustClientBuilder.fromAmbientOidc(
        "https://trust.certlocker.io",
        "https://trust.certlocker.io/oidc/<accountId>");
```

Or:

```java
TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .oidcAudience("https://trust.certlocker.io/oidc/<accountId>")
        .preferAmbientOidc(true)
        .build();
```

Provider notes:

| Provider | Detection | Needs Trust audience |
|----------|-----------|----------------------|
| GitHub Actions | `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (`permissions: id-token: write`) | Yes |
| GCP | GCE / GKE / Cloud Run metadata | Yes |
| Azure | App Service identity or IMDS | Yes |
| Azure DevOps | `SYSTEM_OIDCREQUESTURI` + `SYSTEM_ACCESSTOKEN` | No (fixed ADO aud) |

Explicit provider exchange (then build a client yourself):

```java
URI trust = URI.create("https://trust.certlocker.io");
String aud = "https://trust.certlocker.io/oidc/<accountId>";

OidcExchangeResult gha = TrustOidcExchange.fromGitHubActions(trust, aud);
OidcExchangeResult gcp = TrustOidcExchange.fromGcp(trust, aud);
OidcExchangeResult azure = TrustOidcExchange.fromAzure(trust, aud);
OidcExchangeResult ado = TrustOidcExchange.fromAzureDevOps(trust);

TrustClient client = TrustClient.builder()
        .url(trust)
        .apiToken(gha.tokenId())
        .accountId(gha.accountId())
        .build();
```

### Device OIDC (enrolled machine)

Mints a short-lived Ed25519 / `EdDSA` JWT from the private key downloaded at enroll, then exchanges for a Trust token. Keep the private key on the machine — never check it in.

```java
TrustClient client = TrustClientBuilder.fromDeviceOidc(
        "https://trust.certlocker.io",
        DeviceOidcConfig.builder()
                .audience("https://trust.certlocker.io/oidc/<accountId>")
                .deviceId("laptop-1")
                .privateKeyPath(Path.of(System.getProperty("user.home"), ".trust", "device.pem"))
                .keyId("device-abc123") // required when the principal enrolled a keyId
                .build());
```

Or mint yourself and call `TrustClientBuilder.fromIdToken(trustUrl, jwt)`.

### Exchange mint types: SECRET / CERTIFICATE / MCP

By default the Gateway uses the matched principal’s `defaultTokenType` (typically `SECRET`). Pass an explicit `TokenType` when the principal allows it:

```java
URI trust = URI.create("https://trust.certlocker.io");
String aud = "https://trust.certlocker.io/oidc/<accountId>";

OidcExchangeResult secret = TrustOidcExchange.fromGitHubActions(trust, aud, TokenType.SECRET);
OidcExchangeResult cert = TrustOidcExchange.fromGcp(trust, aud, TokenType.CERTIFICATE);
OidcExchangeResult mcp = TrustOidcExchange.fromAzure(trust, aud, TokenType.MCP);

// Device / raw JWT:
OidcExchangeResult deviceMcp = TrustOidcExchange.fromDeviceOidc(
        trust,
        DeviceOidcConfig.builder()
                .audience(aud)
                .deviceId("laptop-1")
                .privateKeyPath(Path.of(System.getProperty("user.home"), ".trust", "device.pem"))
                .build(),
        TokenType.MCP);

TrustClient client = TrustClient.builder()
        .url(trust)
        .apiToken(secret.tokenId())
        .accountId(secret.accountId())
        .build();
```

`OidcExchangeResult.tokenType()` reports what was minted. Builder helpers (`fromAmbientOidc`, `fromDeviceOidc`, `fromIdToken`) use the principal default.

### 2FA / access-code step-up

User-bound tokens may require an access code on Gateway calls. Configure a prompt on the builder:

```java
TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .accountId("<accountId>")
        .apiToken("<user-bound-token>")
        .authCodePrompt(new ConsoleAuthCodePrompt())
        // or: .authCodePrompt(reason -> /* read code */)
        .build();
```

`ConsoleAuthCodePrompt` reads from stdin. Custom `AuthCodePrompt` implementations can use Gradle / IDE input.

## Using TrustService

```java
try (TrustService service = new TrustService(TrustClient.builder()
        .url("https://trust.certlocker.io")
        .accountId("<accountId>")
        .apiToken("<token>"))) {
    Secret secret = service.getSecret("mvusgvkv5");
    Configuration configuration = service.getSecretAsConfiguration("mvusgvkv5");
    Pem pem = service.getSecretAsPem("b5fqj6c8d");
    Password password = service.getSecretAsPassword("v5q7pspif");
    Credentials cred = service.getSecretAsCredentials("17bu1p62uq");
    PrivateKey privateKey = service.getSecretAsPrivateKey("k8m7c8pps");

    Certificate certificate = service.getCertificate("certificate-token-id");
    String pemLeaf = service.fetchCertificate("certificate-token-id");
    String bundle = service.fetchCertificateBundle("certificate-token-id");

    Token token = service.getToken("tokenId");
} catch (TrustClientException ex) {
    System.err.println(ex.getMessage());
}
```

Closing `TrustService` closes the underlying client.

## HTTP client

The builder accepts the same settings as `HttpClient.Builder`. Default connect timeout is 10 seconds.

```java
TrustClient client = TrustClient.builder()
        .url("https://trust.certlocker.io")
        .accountId("<accountId>")
        .apiToken("<token>")
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .version(HttpClient.Version.HTTP_1_1)
        .build();
```

Pass an existing JDK builder with `.httpClientBuilder(...)` (call it before other HTTP methods when combining). Also accepts `cookieHandler`, `sslContext`, `sslParameters`, `executor`, `priority`, `proxy`, `authenticator`, and `localAddress`.

## License

Licensed under GNU General Public License v3.0. See [LICENSE](LICENSE).

## Publishing

See [docs/publishing.md](docs/publishing.md) for Sonatype setup and GitHub release publishing.

## Gateway rollout compatibility (2026-11-04)

Legacy Gateway URLs and the new account-scoped URLs are both supported. Select
the mode explicitly during rollout; authentication or authorization failures never
trigger a retry against the other mode. The account must belong to the token.

```java
// Existing Gateway:
var client = TrustClient.builder().url("https://trust.certlocker.io")
        .apiToken(token).legacyApi(true).build();
// New Gateway: omit legacyApi(true), and provide accountId(accountId).
```

Base URLs omit `/rest`. Certificate methods take a CERTIFICATE access-token ID,
not a certificate asset ID; null/blank uses the configured API token. Assigned
secret metadata first resolves `secret_id`/`secretId` from token metadata. OIDC
exchange accepts snake_case and camelCase responses and sends both request aliases.

Validation: `./gradlew test` exercises both URL modes, assigned resources, encoded
IDs, denial without fallback, and both OIDC JSON contracts. Default tests no
longer call live services or contain embedded live credentials. This Java client
was tested locally; live Java/real workload OIDC was not run.

Version 1.0.5 must be published before releasing Gradle plugin 1.0.3. For local
integration testing, run `./gradlew test publishToMavenLocal`, then in the plugin
run `./gradlew test -PuseMavenLocal=true`. No remote artifacts were published.
