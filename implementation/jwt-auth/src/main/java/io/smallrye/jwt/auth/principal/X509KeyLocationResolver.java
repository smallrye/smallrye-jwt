/*
 *   Copyright 2020 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jwt.auth.principal;

import java.security.Key;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.JsonWebSignature;
import io.smallrye.jwt.auth.JwsHeaders;
import io.smallrye.jwt.auth.UnresolvableKeyException;
import io.smallrye.jwt.auth.VerificationKeyResolver;

public class X509KeyLocationResolver extends AbstractKeyLocationResolver implements VerificationKeyResolver {

    private List<X509Certificate> certificates;

    public X509KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        super(authContextInfo);

        try {
            initializeInternalResolver();
            if (certificates == null || certificates.isEmpty()) {
                throw PrincipalMessages.msg.failedToLoadCertificates();
            }
        } catch (Exception e) {
            reportLoadKeyException(authContextInfo.getPublicKeyContent(), authContextInfo.getPublicKeyLocation(), e);
        }
    }

    @Override
    public Key resolveKey(JsonWebSignature jws)
            throws UnresolvableKeyException {
        JwsHeaders headers = jws.headers();
        String x5t = headers.x509CertificateThumbprint();
        String x5tS256 = headers.x509CertificateSha256Thumbprint();
        if (certificates == null || certificates.isEmpty()) {
            throw PrincipalMessages.msg.failedToLoadCertificates();
        }

        if (x5t == null && x5tS256 == null) {
            throw PrincipalMessages.msg.failedToLoadKeyWhileResolving();
        }

        for (X509Certificate cert : certificates) {
            try {
                if (x5tS256 != null) {
                    byte[] thumbprint = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
                    String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint);
                    if (x5tS256.equals(computed)) {
                        return cert.getPublicKey();
                    }
                }
                if (x5t != null) {
                    byte[] thumbprint = MessageDigest.getInstance("SHA-1").digest(cert.getEncoded());
                    String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint);
                    if (x5t.equals(computed)) {
                        return cert.getPublicKey();
                    }
                }
            } catch (Exception e) {
                // try next
            }
        }

        throw PrincipalMessages.msg.failedToLoadKeyWhileResolving();
    }

    protected void initializeInternalResolver() throws Exception {

        if (initializeHttpsJwks(authContextInfo.getPublicKeyLocation())) {
            initializeCertificatesFromJwks(remoteJwkSet.getKeys());
            return;
        }

        String content = authContextInfo.getPublicKeyContent() != null
                ? authContextInfo.getPublicKeyContent()
                : readKeyContent(authContextInfo.getPublicKeyLocation());

        if (mayBeFormat(KeyFormat.JWK) || mayBeFormat(KeyFormat.JWK_BASE64URL)) {
            loadFromJwk(content, null, null);
            if (jsonWebKeys != null) {
                initializeCertificatesFromJwks(jsonWebKeys);
                return;
            }
        }

        initializeCertificatesFromPEM(content);
    }

    private void initializeCertificatesFromJwks(List<JWK> jwks) throws Exception {
        List<X509Certificate> certs = new LinkedList<>();
        Set<String> signatureAlgorithms = signatureAlgorithms(authContextInfo);
        for (JWK jwk : jwks) {
            String jwkAlg = jwk.getAlgorithm() != null ? jwk.getAlgorithm().getName() : null;
            if (jwkAlg == null || signatureAlgorithms.contains(jwkAlg)) {
                if (jwk instanceof RSAKey) {
                    RSAKey rsaKey = (RSAKey) jwk;
                    List<com.nimbusds.jose.util.Base64> x5c = rsaKey.getX509CertChain();
                    if (x5c != null && !x5c.isEmpty()) {
                        X509Certificate cert = X509CertUtils.parse(x5c.get(0).decode());
                        if (cert != null) {
                            certs.add(cert);
                        }
                    }
                }
            }
        }
        this.certificates = certs;
    }

    void initializeCertificatesFromPEM(String content) {
        X509Certificate cert = super.loadPEMCertificate(content);
        if (cert != null) {
            this.certificates = Collections.singletonList(cert);
        }
    }

    private Set<String> signatureAlgorithms(JWTAuthContextInfo authContextInfo) {
        Set<String> algorithms = new HashSet<>();
        for (SignatureAlgorithm keyEncAlgo : authContextInfo.getSignatureAlgorithm()) {
            algorithms.add(keyEncAlgo.getAlgorithm());
        }
        return algorithms;
    }
}
