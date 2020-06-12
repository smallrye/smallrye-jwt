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
package io.smallrye.jwt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.URL;

public final class ResourceUtils {

    public static final String HTTP_BASED_SCHEME = "http";
    public static final String CLASSPATH_SCHEME = "classpath:";
    public static final String FILE_SCHEME = "file:";

    private ResourceUtils() {
    }

    public static String readResource(String resourceLocation) throws IOException {

        return readResource(resourceLocation, null);
    }

    public static String readResource(String resourceLocation, UrlStreamResolver urlResolver) throws IOException {

        InputStream is = null;

        if (resourceLocation.startsWith(HTTP_BASED_SCHEME)) {
            // It can be PEM key at HTTP or HTTPS URL, JWK set at HTTP URL or single JWK at either HTTP or HTTPS URL
            is = (urlResolver == null ? getUrlResolver() : urlResolver).resolve(resourceLocation);
        } else if (resourceLocation.startsWith(FILE_SCHEME)) {
            is = getAsFileSystemResource(resourceLocation.substring(FILE_SCHEME.length()));
        } else if (resourceLocation.startsWith(CLASSPATH_SCHEME)) {
            is = getAsClasspathResource(resourceLocation.substring(CLASSPATH_SCHEME.length()));
        } else {
            is = getAsFileSystemResource(resourceLocation);
            if (is == null) {
                is = getAsClasspathResource(resourceLocation);
            }
            if (is == null) {
                is = getUrlResolver().resolve(resourceLocation);
            }
        }

        if (is == null) {
            return null;
        }

        StringWriter contents = new StringWriter();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                contents.write(line);
            }
        }
        return contents.toString();
    }

    public static UrlStreamResolver getUrlResolver() {
        return new UrlStreamResolver();
    }

    public static InputStream getAsFileSystemResource(String publicKeyLocation) throws IOException {
        try {
            return new FileInputStream(publicKeyLocation);
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    public static InputStream getAsClasspathResource(String location) {
        InputStream is = ResourceUtils.class.getResourceAsStream(location);
        if (is == null) {
            is = Thread.currentThread().getContextClassLoader().getResourceAsStream(location);
        }
        return is;
    }

    public static class UrlStreamResolver {
        public InputStream resolve(String keyLocation) throws IOException {
            return new URL(keyLocation).openStream();
        }
    }
}
