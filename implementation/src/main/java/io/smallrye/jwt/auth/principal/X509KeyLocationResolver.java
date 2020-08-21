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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.KeyUtils;

public class X509KeyLocationResolver extends AbstractKeyLocationResolver implements VerificationKeyResolver {

    private X509VerificationKeyResolver resolver;

    public X509KeyLocationResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        super(authContextInfo);

        try {
            initializeInternalResolver();
            if (resolver == null) {
                throw PrincipalMessages.msg.failedToLoadCertificates();
            }
        } catch (Exception e) {
            reportLoadKeyException(authContextInfo.getPublicKeyContent(), authContextInfo.getPublicKeyLocation(), e);
        }
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        return resolver.resolveKey(jws, nestingContext);
    }

    protected void initializeInternalResolver() throws Exception {

        if (isHttpsJwksInitialized(authContextInfo.getPublicKeyLocation())) {
            initializeInternalResolverFromJwks(httpsJwks.getJsonWebKeys());
            return;
        }

        String content = authContextInfo.getPublicKeyContent() != null
                ? authContextInfo.getPublicKeyContent()
                : readKeyContent(authContextInfo.getPublicKeyLocation());

        if (mayBeFormat(KeyFormat.JWK) || mayBeFormat(KeyFormat.JWK_BASE64URL)) {
            loadFromJwk(content, null, null);
            if (jsonWebKeys != null) {
                initializeInternalResolverFromJwks(jsonWebKeys);
                return;
            }
        }

        initializeInternalResolverFromPEMCertificate(content);
    }

    private void initializeInternalResolverFromJwks(List<JsonWebKey> jsonWebKeys) throws Exception {
        List<X509Certificate> certs = new LinkedList<>();
        for (JsonWebKey jwk : jsonWebKeys) {
            if (jwk.getAlgorithm() == null || authContextInfo.getSignatureAlgorithm().getAlgorithm().equals(jwk.getAlgorithm())
                    && jwk instanceof RsaJsonWebKey) {
                // Get the certificate chain
                List<X509Certificate> x5c = ((RsaJsonWebKey) jwk).getCertificateChain();
                if (x5c == null) {
                    // required in the HTTPS JWKS case
                    @SuppressWarnings("unchecked")
                    List<String> encodedChain = jwk.getOtherParameterValue("x5c", List.class);
                    if (encodedChain != null && !encodedChain.isEmpty()) {
                        x5c = Collections.singletonList(KeyUtils.getCertificate(encodedChain.get(0)));
                    }
                }
                if (x5c != null && x5c.size() > 0) {
                    // The 1st certificate must contain the key
                    certs.add(x5c.get(0));
                }
            }
        }
        resolver = new X509VerificationKeyResolver(certs);
    }

    void initializeInternalResolverFromPEMCertificate(String content) {
        X509Certificate cert = super.loadPEMCertificate(content);
        if (cert != null) {
            resolver = new X509VerificationKeyResolver(cert);
        }
    }
}
