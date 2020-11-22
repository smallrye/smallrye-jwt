/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
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

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * A parser to parse a JWT token and convert it to a {@link JsonWebToken}.
 */
public interface JWTParser {

    /**
     * Parse JWT token.
     * The token will be verified or decrypted or decrypted and then verified and converted to {@link JsonWebToken}.
     * This method depends on the injected {@link JWTAuthContextInfo} configuration context.
     *
     * @param token the JWT token
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken parse(final String token) throws ParseException;

    /**
     * Parse JWT token.
     * The token will be verified or decrypted or decrypted and then verified and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param context the configuration context which will override the injected {@link JWTAuthContextInfo} configuration
     *        context.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken parse(final String token, JWTAuthContextInfo context) throws ParseException;

    /**
     * Parse JWT token. The token will be verified and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param key the public verification key. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its publicVerificationKey property will be replaced by this parameter.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken verify(final String token, PublicKey key) throws ParseException;

    /**
     * Parse JWT token. The token will be verified and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param key the secret verification key. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its secretVerificationKey property will be replaced by this parameter.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken verify(final String token, SecretKey key) throws ParseException;

    /**
     * Parse JWT token. The token will be verified and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param secret the secret. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its secretVerificationKey property will be replaced after
     *        converting this parameter to {@link SecretKey}.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken verify(final String token, String secret) throws ParseException;

    /**
     * Parse JWT token. The token will be decrypted and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param key the private decryption key. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its privateDecryptionkey property will be replaced by this parameter.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken decrypt(final String token, PrivateKey key) throws ParseException;

    /**
     * Parse JWT token. The token will be decrypted and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param key the secret decryption key. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its secretDecryptionkey property will be replaced by this parameter.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken decrypt(final String token, SecretKey key) throws ParseException;

    /**
     * Parse JWT token. The token will be decrypted and converted to {@link JsonWebToken}.
     *
     * @param token the JWT token
     * @param secret the secret. The injected {@link JWTAuthContextInfo} configuration context
     *        will be reused, only its secretDecryptionkey property will be replaced will be replaced after
     *        converting this parameter to {@link SecretKey}.
     * @return JsonWebToken
     * @throws ParseException parse exception
     */
    public JsonWebToken decrypt(final String token, String secret) throws ParseException;

}
