# Publishing the Java client

The public coordinate is `io.certlocker:trust-client:1.0.1`. Consumers use Maven Central without credentials. This repository publishes the Java library; `certlocker-io/trust-gradle-plugin` publishes the separate `io.certlocker.trust` Gradle plugin.

## One-time account setup

1. Sign in to [Sonatype Central](https://central.sonatype.com/). This is Sonatype, not SonarCloud/SonarQube.
2. Request namespace `io.certlocker` under Publishing → Namespaces. Add the exact DNS TXT record Sonatype supplies to `certlocker.io`, check it resolves, then request verification. If the namespace is already registered, use its existing authorized account rather than registering it again.
3. Generate a [Central user token](https://central.sonatype.com/usertoken). The generated username and password are publishing credentials, separate from the account login.
4. Create or select a dedicated, passphrase-protected OpenPGP signing key. Follow [Sonatype's signing guide](https://central.sonatype.org/publish/requirements/gpg/) to distribute its public key to a supported keyserver. Keep a backup of the private key and revocation certificate.
5. In [repository Actions secrets](https://github.com/certlocker-io/trust-java-client/settings/secrets/actions), add:

| Secret | Value |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | Generated Central token username |
| `MAVEN_CENTRAL_PASSWORD` | Generated Central token password |
| `MAVEN_SIGNING_KEY` | Complete ASCII-armored private signing key, with real newlines |
| `MAVEN_SIGNING_PASSWORD` | Signing key passphrase |

Export the private key directly into GitHub secrets without printing it into a terminal transcript:

```bash
gpg --armor --export-secret-keys YOUR_KEY_FINGERPRINT | gh secret set MAVEN_SIGNING_KEY --repo certlocker-io/trust-java-client
```

Set the other values through GitHub's UI or interactive `gh secret set`. Do not paste credentials into issues or chat. These are publishing credentials; `TRUST_API_KEY` is unrelated and is not needed by CI.

## Release

1. Merge the publishing changes into `main`, and make sure Build passes.
2. Set `trustClientVersion` in `gradle.properties` to a new stable version and merge it. For the first release it is `1.0.1`.
3. Create a GitHub Release from `main` with the matching tag, e.g. `v1.0.1`. Publishing a stable GitHub Release starts **Publish release**. Draft and prerelease releases do not publish.
4. The workflow checks tag/version agreement and membership in `main`, builds and tests without credentials, then signs and uploads the JAR, sources, Javadoc, POM and metadata. It automatically requests publication and waits for Central's `PUBLISHED` state.
5. Confirm the POM resolves at `https://repo.maven.apache.org/maven2/io/certlocker/trust-client/1.0.1/trust-client-1.0.1.pom`. Allow time for repository propagation before publishing the Gradle plugin.

Ordinary pushes and pull requests only build. Each public release needs a new version: Central coordinates are immutable. To retry a failed upload, use Actions → Publish release → Run workflow and supply the existing tag. First inspect the Central deployment: if it is already published, do not upload it again; if still processing, wait for its outcome.

## Local verification

Use JDK 21:

```bash
./gradlew build generatePomFileForMavenPublication
./gradlew publishToMavenLocal
```

The second command is an unsigned local installation for plugin development, never a Central release. Normal tests are offline and do not fetch live secrets.

Configuration and environment variables follow the [Maven Publish plugin guide](https://vanniktech.github.io/gradle-maven-publish-plugin/central/). Account verification, public-key distribution and GitHub secret creation are still required before a real publication can succeed.
