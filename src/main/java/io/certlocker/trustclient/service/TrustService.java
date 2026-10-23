package io.certlocker.trustclient.service;

import io.certlocker.trustclient.client.TrustClient;
import io.certlocker.trustclient.client.TrustClientBuilder;
import io.certlocker.trustclient.exception.TrustClientException;
import io.certlocker.trustclient.model.certificate.Certificate;
import io.certlocker.trustclient.model.secret.*;
import io.certlocker.trustclient.model.token.Token;

/**
 * Typed access to Trust secrets, certificates and tokens.
 * <p>
 * {@code get} methods return the asset record. {@code fetch} methods return the asset contents.
 * Closing this service closes the underlying {@link TrustClient}.
 *
 * @author dhudson
 * 22/10/2026 - 14:41
 */
public class TrustService implements AutoCloseable {

    private final TrustClient theTrustClient;

    /**
     * Creates a service for an existing client.
     *
     * @param trustClient client used for requests
     */
    public TrustService(TrustClient trustClient) {
        theTrustClient = trustClient;
    }

    /**
     * Creates a service from a builder. The builder is built immediately.
     *
     * @param trustClientBuilder builder for the client this service owns
     */
    public TrustService(TrustClientBuilder trustClientBuilder) {
        this(trustClientBuilder.build());
    }

    /**
     * Returns the contents of the secret.
     *
     * @param id secret identifier
     * @return secret contents
     * @throws TrustClientException if the request fails
     */
    public String fetchSecret(String id) throws TrustClientException {
        return theTrustClient.fetchSecret(theTrustClient.getSecret(id));
    }

    /**
     * Returns the secret record.
     *
     * @param id secret identifier
     * @return the secret, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Secret getSecret(String id) throws TrustClientException {
        String value = theTrustClient.getSecret(id);
        if (value != null) {
            return MapperService.getMapper().readValue(value, Secret.class);
        }
        return null;
    }

    /**
     * Returns the secret contents as a PEM secret.
     *
     * @param id secret identifier
     * @return the PEM secret, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Pem getSecretAsPem(String id) throws TrustClientException {
        return getSecretAs(id, Pem.class);
    }

    /**
     * Returns the secret contents as a configuration secret.
     *
     * @param id secret identifier
     * @return the configuration secret
     * @throws TrustClientException if the request fails
     */
    public Configuration getSecretAsConfiguration(String id) throws TrustClientException {
        return new Configuration(theTrustClient.fetchSecret(id));
    }

    /**
     * Returns the secret contents as a private key.
     *
     * @param id secret identifier
     * @return the private key, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public PrivateKey getSecretAsPrivateKey(String id) throws TrustClientException {
        return getSecretAs(id, PrivateKey.class);
    }

    /**
     * Returns the secret contents as a password.
     *
     * @param id secret identifier
     * @return the password secret
     * @throws TrustClientException if the request fails
     */
    public Password getSecretAsPassword(String id) throws TrustClientException {
        return new Password(theTrustClient.fetchSecret(id));
    }

    /**
     * Returns the secret contents as credentials.
     *
     * @param id secret identifier
     * @return the credentials, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Credentials getSecretAsCredentials(String id) throws TrustClientException {
        return getSecretAs(id, Credentials.class);
    }

    private <T> T getSecretAs(String id, Class<T> type) throws TrustClientException {
        String value = theTrustClient.fetchSecret(id);
        if (value != null) {
            return MapperService.getMapper().readValue(value, type);
        }
        return null;
    }

    /**
     * Returns the certificate record.
     *
     * @param id certificate identifier
     * @return the certificate, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Certificate getCertificate(String id) throws TrustClientException {
        String value = theTrustClient.fetchCertificate(id);
        if (value != null) {
            return MapperService.getMapper().readValue(value, Certificate.class);
        }
        return null;
    }

    /**
     * Returns the certificate contents.
     *
     * @param id certificate identifier
     * @return certificate contents
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificate(String id) throws TrustClientException {
        return theTrustClient.fetchCertificate(id);
    }

    /**
     * Returns the certificate bundle.
     *
     * @param id certificate identifier
     * @return certificate bundle
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificateBundle(String id) throws TrustClientException {
        return theTrustClient.fetchCertificateBundle(id);
    }

    /**
     * Returns the token record.
     *
     * @param id token identifier
     * @return the token, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Token getToken(String id) throws TrustClientException {
        String value = theTrustClient.getToken(id);
        if (value != null) {
            return MapperService.getMapper().readValue(value, Token.class);
        }
        return null;
    }

    /**
     * Closes the underlying {@link TrustClient}.
     */
    @Override
    public void close() {
        theTrustClient.close();
    }
}
