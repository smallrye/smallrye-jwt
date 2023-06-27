package io.smallrye.jwt.auth.principal;

import java.io.IOException;
import java.security.Key;
import java.util.List;

import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import io.smallrye.jwt.auth.principal.AbstractKeyLocationResolver.TrustAllHostnameVerifier;
import io.smallrye.jwt.auth.principal.AbstractKeyLocationResolver.TrustedHostsHostnameVerifier;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

public class AwsAlbKeyResolver implements VerificationKeyResolver {

    private JWTAuthContextInfo authContextInfo;

    public AwsAlbKeyResolver(JWTAuthContextInfo authContextInfo) throws UnresolvableKeyException {
        if (authContextInfo.getPublicKeyLocation() == null) {
            throw PrincipalMessages.msg.nullKeyLocation();
        }
        this.authContextInfo = authContextInfo;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException {
        String kid = jws.getHeaders().getStringHeaderValue(JsonWebKey.KEY_ID_PARAMETER);
        ;
        verifyKid(kid);
        String keyLocation = authContextInfo.getPublicKeyLocation() + "/" + kid;
        SimpleResponse simpleResponse = null;
        try {
            simpleResponse = getHttpGet().get(keyLocation);
        } catch (IOException ex) {
            AbstractKeyLocationResolver.reportLoadKeyException(null, keyLocation, ex);
        }
        String keyContent = simpleResponse.getBody();
        try {
            return KeyUtils.decodePublicKey(keyContent, authContextInfo.getSignatureAlgorithm());
        } catch (Exception e) {
            AbstractKeyLocationResolver.reportUnresolvableKeyException(keyContent, keyLocation);
        }
        return null;
    }

    protected SimpleGet getHttpGet() throws UnresolvableKeyException {
        Get httpGet = new Get();
        if (authContextInfo.isTlsTrustAll()) {
            httpGet.setHostnameVerifier(new TrustAllHostnameVerifier());
        } else if (authContextInfo.getTlsTrustedHosts() != null) {
            httpGet.setHostnameVerifier(new TrustedHostsHostnameVerifier(authContextInfo.getTlsTrustedHosts()));
        }
        if (authContextInfo.getTlsCertificate() != null) {
            httpGet.setTrustedCertificates(
                    AbstractKeyLocationResolver.loadPEMCertificate(authContextInfo.getTlsCertificate()));
        } else if (authContextInfo.getTlsCertificatePath() != null) {
            httpGet.setTrustedCertificates(AbstractKeyLocationResolver.loadPEMCertificate(
                    readKeyContent(authContextInfo.getTlsCertificatePath())));
        }
        return httpGet;
    }

    protected String readKeyContent(String keyLocation) throws UnresolvableKeyException {
        try {
            String content = ResourceUtils.readResource(keyLocation);
            if (content == null) {
                throw PrincipalMessages.msg.resourceNotFound(keyLocation);
            }
            return content;
        } catch (IOException ex) {
            AbstractKeyLocationResolver.reportLoadKeyException(null, keyLocation, ex);
            return null;
        }
    }

    private void verifyKid(String kid) throws UnresolvableKeyException {
        if (kid == null) {
            throw PrincipalMessages.msg.nullKeyIdentifier();
        }
        String expectedKid = authContextInfo.getTokenKeyId();
        if (expectedKid != null && kid != null && !kid.equals(expectedKid)) {
            PrincipalLogging.log.invalidTokenKidHeader(kid, expectedKid);
            throw PrincipalMessages.msg.invalidTokenKid();
        }
    }
}
