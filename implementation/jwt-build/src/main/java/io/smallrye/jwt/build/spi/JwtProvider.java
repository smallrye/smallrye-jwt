package io.smallrye.jwt.build.spi;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.smallrye.jwt.build.JwtClaimsBuilder;

/**
 * Service provider for JWT Claims Builder objects.
 *
 * @see ServiceLoader
 */
public abstract class JwtProvider {
    /**
     * Name of the default {@code JwtProvider} implementation class.
     */
    private static final String DEFAULT_JWT_PROVIDER = "io.smallrye.jwt.build.impl.JwtProviderImpl";
    private volatile static JwtProvider provider;

    protected JwtProvider() {
    }

    /**
     * Creates a JWT provider object. The provider is loaded using the
     * {@link ServiceLoader#load(Class)} method. If there are no available
     * service providers, this method returns the default service provider.
     * Users are recommended to cache the result of this method.
     *
     * @see ServiceLoader
     * @return a JWT provider
     */
    public static JwtProvider provider() {
        if (provider == null) {
            synchronized (JwtProvider.class) {
                if (provider == null) {
                    provider = getProvider();
                }
            }
        }
        return provider;
    }

    private static JwtProvider getProvider() {
        ServiceLoader<JwtProvider> loader = ServiceLoader.load(JwtProvider.class);
        Iterator<JwtProvider> it = loader.iterator();
        if (it.hasNext()) {
            return it.next();
        }
        try {
            return (JwtProvider) Class.forName(DEFAULT_JWT_PROVIDER).newInstance();
        } catch (ClassNotFoundException ex) {
            throw SpiMessages.msg.providerNotFound(DEFAULT_JWT_PROVIDER, ex.getMessage(), ex);
        } catch (IllegalAccessException ex) {
            throw SpiMessages.msg.providerClassCannotBeAccessed(DEFAULT_JWT_PROVIDER, ex.getMessage(), ex);
        } catch (InstantiationException ex) {
            throw SpiMessages.msg.providerCannotBeInstantiated(DEFAULT_JWT_PROVIDER, ex.getMessage(), ex);
        }
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder}
     *
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims();

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a map of claims.
     *
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@link Boolean}, {@link Number}, {@link Collection}, {@link Map},
     *        {@link JsonObject} or {@link JsonArray}.
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(Map<String, Object> claims);

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from {@link JsonObject}
     *
     * @param jsonObject {@link JsonObject} containing the claims.
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(JsonObject jsonObject);

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a JSON resource.
     *
     * @param jsonLocation JSON resource location
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(String jsonLocation);

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a JSON string.
     *
     * @param json JSON string
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claimsJson(String json);

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from {@link JsonWebToken}.
     *
     * @param jwt JsonWebToken token.
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(JsonWebToken jwt);

}
