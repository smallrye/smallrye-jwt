package io.smallrye.jwt.auth.principal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

public class AwsAlbTokenTest {

    private static final String AWS_ALB_KEY = "-----BEGIN PUBLIC KEY-----"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjPHY1j9umvc8nZEswOzs+lPpLKLn"
            + "qCBqvyZGJfBlXapmtGiqYEwpIqh/lZdkr4wDii7CP1DzIUSHONbc+jufiQ=="
            + "-----END PUBLIC KEY-----";

    private static final String JWT = "eyJ0eXAiOiJKV1QiLCJraWQiOiJjMmY4MGM4Yi1jMDVjLTQwNjgtYWYxNC0xNzI5OWY3ODk2YjEiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtY2VudHJhbC0xLmFtYXpvbmF3cy5jb20vZXUtY2VudHJhbC0xX015UnJPQ0hRdyIsImNsaWVudCI6IjRmbXZodDIydGpyZ2Q3ZDNrM3RnaHR0Y3Q3Iiwic2lnbmVyIjoiYXJuOmF3czplbGFzdGljbG9hZGJhbGFuY2luZzpldS1jZW50cmFsLTE6MTk3MjgwOTU4MjI1OmxvYWRiYWxhbmNlci9hcHAvZWNzLXdpdGgtY29nbml0by1sYi82Mjg0YmU2NWI4MjdjNTk4IiwiZXhwIjoxNjg3NzQ4MDQ1fQ=="
            + ".eyJzdWIiOiIyM2Q0OThiMi0zMDMxLTcwZDItOGExNS00OWRkODg2YTA4N2IiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6ImR1a2VAc3VuLmNvbSIsInVzZXJuYW1lIjoiZHVrZSIsImV4cCI6MTY4Nzc0ODA0NSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5ldS1jZW50cmFsLTEuYW1hem9uYXdzLmNvbS9ldS1jZW50cmFsLTFfTXlSck9DSFF3In0="
            + ".Jd7RXHsOj8vw2b4irZCxxWO-0UQBZ2X1bRNsKZ9D02JWJaNOvOnrV8T-qrcmWNpl7MjNhsGSm1C4e2rAjaF0jg==";

    @Test
    void parseToken() throws Exception {
        JWTAuthContextInfo config = new JWTAuthContextInfo();
        config.setPublicKeyContent(AWS_ALB_KEY);
        config.setIssuedBy("https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_MyRrOCHQw");
        // ES256 is used to sign
        config.setSignatureAlgorithm(Set.of(SignatureAlgorithm.ES256));
        // Token has no `iat`
        config.setMaxTimeToLiveSecs(-1L);
        // It has already expired so for the test to pass the clock skew has to be set
        config.setClockSkew(Integer.MAX_VALUE);
        JWTParser parser = new DefaultJWTParser(config);
        JsonWebToken jwt = parser.parse(JWT);
        assertEquals("duke", jwt.getClaim("username"));
    }
}
