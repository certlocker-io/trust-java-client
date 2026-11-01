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
 * <p>
 * An asset token is an {@code x-api-token} assigned to one secret or one certificate.
 * Trust already knows that asset, so the no-argument methods send no id.
 * Pass an id when the token is not assigned to a single asset.
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
     * <p>
     * Use {@link #fetchSecret()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return secret contents
     * @throws TrustClientException if the request fails
     */
    public String fetchSecret(String id) throws TrustClientException {
        return theTrustClient.fetchSecret(id);
    }

    /**
     * Returns the contents of the secret assigned to the API token.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return secret contents
     * @throws TrustClientException if the request fails
     */
    public String fetchSecret() throws TrustClientException {
        return theTrustClient.fetchSecret(null);
    }

    /**
     * Returns the secret record.
     * <p>
     * Use {@link #getSecret()} when the API token is a secret token assigned to this secret.
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
     * Returns the secret record assigned to the API token.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the secret, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Secret getSecret() throws TrustClientException {
        return getSecret(null);
    }

    /**
     * Returns the secret contents as a PEM secret.
     * <p>
     * Use {@link #getSecretAsPem()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return the PEM secret, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Pem getSecretAsPem(String id) throws TrustClientException {
        return getSecretAs(id, Pem.class);
    }

    /**
     * Returns the assigned secret as a PEM secret.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the PEM secret, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Pem getSecretAsPem() throws TrustClientException {
        return getSecretAsPem(null);
    }

    /**
     * Returns the secret contents as a configuration secret.
     * <p>
     * Use {@link #getSecretAsConfiguration()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return the configuration secret
     * @throws TrustClientException if the request fails
     */
    public Configuration getSecretAsConfiguration(String id) throws TrustClientException {
        return new Configuration(theTrustClient.fetchSecret(id));
    }

    /**
     * Returns the assigned secret as a configuration secret.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the configuration secret
     * @throws TrustClientException if the request fails
     */
    public Configuration getSecretAsConfiguration() throws TrustClientException {
        return getSecretAsConfiguration(null);
    }

    /**
     * Returns the secret contents as a private key.
     * <p>
     * Use {@link #getSecretAsPrivateKey()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return the private key, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public PrivateKey getSecretAsPrivateKey(String id) throws TrustClientException {
        return getSecretAs(id, PrivateKey.class);
    }

    /**
     * Returns the assigned secret as a private key.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the private key, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public PrivateKey getSecretAsPrivateKey() throws TrustClientException {
        return getSecretAsPrivateKey(null);
    }

    /**
     * Returns the secret contents as a password.
     * <p>
     * Use {@link #getSecretAsPassword()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return the password secret
     * @throws TrustClientException if the request fails
     */
    public Password getSecretAsPassword(String id) throws TrustClientException {
        return new Password(theTrustClient.fetchSecret(id));
    }

    /**
     * Returns the assigned secret as a password.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the password secret
     * @throws TrustClientException if the request fails
     */
    public Password getSecretAsPassword() throws TrustClientException {
        return getSecretAsPassword(null);
    }

    /**
     * Returns the secret contents as credentials.
     * <p>
     * Use {@link #getSecretAsCredentials()} when the API token is a secret token assigned to this secret.
     *
     * @param id secret identifier
     * @return the credentials, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Credentials getSecretAsCredentials(String id) throws TrustClientException {
        return getSecretAs(id, Credentials.class);
    }

    /**
     * Returns the assigned secret as credentials.
     * <p>
     * The token is a secret token bound to one secret. Trust selects that secret, so no id is sent.
     *
     * @return the credentials, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Credentials getSecretAsCredentials() throws TrustClientException {
        return getSecretAsCredentials(null);
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
     * <p>
     * Use {@link #getCertificate()} when the API token is a certificate token assigned to this certificate.
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
     * Returns the certificate record assigned to the API token.
     * <p>
     * The token is a certificate token bound to one certificate. Trust selects that certificate, so no id is sent.
     *
     * @return the certificate, or {@code null} when the response body is null
     * @throws TrustClientException if the request fails
     */
    public Certificate getCertificate() throws TrustClientException {
        return getCertificate(null);
    }

    /**
     * Returns the certificate contents.
     * <p>
     * Use {@link #fetchCertificate()} when the API token is a certificate token assigned to this certificate.
     *
     * @param id certificate identifier
     * @return certificate contents
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificate(String id) throws TrustClientException {
        return theTrustClient.fetchCertificate(id);
    }

    /**
     * Returns the contents of the certificate assigned to the API token.
     * <p>
     * The token is a certificate token bound to one certificate. Trust selects that certificate, so no id is sent.
     *
     * @return certificate contents
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificate() throws TrustClientException {
        return fetchCertificate(null);
    }

    /**
     * Returns the certificate bundle.
     * <p>
     * Use {@link #fetchCertificateBundle()} when the API token is a certificate token assigned to this certificate.
     *
     * @param id certificate identifier
     * @return certificate bundle
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificateBundle(String id) throws TrustClientException {
        return theTrustClient.fetchCertificateBundle(id);
    }

    /**
     * Returns the bundle of the certificate assigned to the API token.
     * <p>
     * The token is a certificate token bound to one certificate. Trust selects that certificate, so no id is sent.
     *
     * @return certificate bundle
     * @throws TrustClientException if the request fails
     */
    public String fetchCertificateBundle() throws TrustClientException {
        return fetchCertificateBundle(null);
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
