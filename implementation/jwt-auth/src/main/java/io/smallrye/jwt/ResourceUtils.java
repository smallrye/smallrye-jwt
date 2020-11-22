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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

@Deprecated
public final class ResourceUtils {

    private ResourceUtils() {
    }

    public static String readResource(String resourceLocation) throws IOException {

        return io.smallrye.jwt.util.ResourceUtils.readResource(resourceLocation);
    }

    public static String readResource(String resourceLocation, UrlStreamResolver urlResolver) throws IOException {

        return io.smallrye.jwt.util.ResourceUtils.readResource(resourceLocation, urlResolver);
    }

    public static UrlStreamResolver getUrlResolver() {
        return new UrlStreamResolver();
    }

    public static InputStream getAsFileSystemResource(String publicKeyLocation) throws IOException {
        return io.smallrye.jwt.util.ResourceUtils.getAsFileSystemResource(publicKeyLocation);
    }

    public static InputStream getAsClasspathResource(String location) {
        return io.smallrye.jwt.util.ResourceUtils.getAsClasspathResource(location);
    }

    public static class UrlStreamResolver extends io.smallrye.jwt.util.ResourceUtils.UrlStreamResolver {
        public InputStream resolve(String keyLocation) throws IOException {
            return new URL(keyLocation).openStream();
        }
    }
}
