package io.certlocker.trustclient.oidc;

import io.certlocker.trustclient.exception.TrustClientException;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DeviceOidcJwtTest {

    /** Dogfood keypair from Trust fixer {@code OidcDeviceKeys} (public only used to verify mint). */
    private static final String DOGFOOD_PRIVATE_PEM = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIF9AaYYFhQwyap4byHSJdP10An9RnSyjIs7938lU7Sm/
            -----END PRIVATE KEY-----
            """;

    private static final String DOGFOOD_PUBLIC_PEM = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAWSHYSlK7bRVNfnJZkuuPdvt8YVdUc4YQlsLB1DfEV3U=
            -----END PUBLIC KEY-----
            """;

    @Test
    public void mintsEdDsaJwtMatchingTrustClaimShape() throws Exception {
        EdECPrivateKey privateKey = DeviceOidcPrivateKey.loadFromPem(DOGFOOD_PRIVATE_PEM);
        String audience = DeviceOidc.audienceForAccount("acct-dogfood");
        String jwt = DeviceOidcJwt.mint(audience, "laptop-dogfood-1", privateKey, "trust-device-dexta", 5);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        assertEquals(AlgorithmIdentifiers.EDDSA, jws.getAlgorithmHeaderValue());
        assertEquals("trust-device-dexta", jws.getKeyIdHeaderValue());

        EdECPublicKey publicKey = loadPublic(DOGFOOD_PUBLIC_PEM);
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setExpectedAudience(audience)
                .setExpectedIssuer(DeviceOidc.DEVICE_ISSUER)
                .setVerificationKey(publicKey)
                .setJwsAlgorithmConstraints(
                        org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT,
                        AlgorithmIdentifiers.EDDSA)
                .build();
        JwtClaims claims = consumer.processToClaims(jwt);
        assertEquals("device:laptop-dogfood-1", claims.getSubject());
        assertEquals("laptop-dogfood-1", claims.getClaimValue("device_id"));
    }

    @Test
    public void loadsPrivateKeyFromFile(@TempDir Path dir) throws Exception {
        Path pemFile = dir.resolve("device.pem");
        Files.writeString(pemFile, DOGFOOD_PRIVATE_PEM, StandardCharsets.UTF_8);
        EdECPrivateKey fromFile = DeviceOidcPrivateKey.loadFromFile(pemFile);
        EdECPrivateKey fromPem = DeviceOidcPrivateKey.loadFromPem(DOGFOOD_PRIVATE_PEM);
        assertEquals(fromPem.getAlgorithm(), fromFile.getAlgorithm());

        String jwt = DeviceOidcJwt.mintFromFile(
                DeviceOidc.audienceForAccount("a1"),
                "dev-1",
                pemFile,
                null,
                2);
        assertEquals(3, jwt.split("\\.").length);
    }

    @Test
    public void rejectsNonPkcs8Pem() {
        TrustClientException ex = assertThrows(TrustClientException.class,
                () -> DeviceOidcPrivateKey.loadFromPem("-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n-----END OPENSSH PRIVATE KEY-----"));
        assertTrue(ex.getMessage().contains("PKCS#8"));
    }

    @Test
    public void configRequiresKeyMaterial() {
        assertThrows(IllegalArgumentException.class, () -> DeviceOidcConfig.builder()
                .audience("https://trust.certlocker.io/oidc/a")
                .deviceId("d1")
                .build());
    }

    @Test
    public void mintsWithGeneratedKeypair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = gen.generateKeyPair();
        EdECPrivateKey privateKey = (EdECPrivateKey) pair.getPrivate();
        String pem = toPkcs8Pem(privateKey);
        EdECPrivateKey reloaded = DeviceOidcPrivateKey.loadFromPem(pem);
        String jwt = DeviceOidcJwt.mint(
                "https://trust.certlocker.io/oidc/acct",
                "machine-1",
                reloaded,
                "kid-1",
                1);
        assertTrue(jwt.startsWith("eyJ"));
    }

    private static EdECPublicKey loadPublic(String pem) throws Exception {
        String stripped = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(stripped);
        return (EdECPublicKey) java.security.KeyFactory.getInstance("Ed25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
    }

    private static String toPkcs8Pem(EdECPrivateKey key) {
        String b64 = Base64.getEncoder().encodeToString(key.getEncoded());
        StringBuilder sb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END PRIVATE KEY-----\n");
        return sb.toString();
    }
}
