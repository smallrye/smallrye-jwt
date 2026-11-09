package io.smallrye.jwt.config;

import org.eclipse.microprofile.config.spi.Converter;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;

public class SignatureAlgorithmConverter implements Converter<SignatureAlgorithm> {

    private static final long serialVersionUID = 1L;

    @Override
    public SignatureAlgorithm convert(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return SignatureAlgorithm.fromAlgorithm(value.trim());
    }
}
