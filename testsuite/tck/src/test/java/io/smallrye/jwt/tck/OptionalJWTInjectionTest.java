package io.smallrye.jwt.tck;

import static io.restassured.RestAssured.given;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static org.eclipse.microprofile.jwt.tck.util.TokenUtils.generateTokenString;
import static org.hamcrest.Matchers.equalTo;

import java.util.Optional;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.annotations.Test;

public class OptionalJWTInjectionTest extends Arquillian {
    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap
                .create(WebArchive.class)
                .addAsResource("publicKey.pem")
                .addClass(TCKApplication.class)
                //.addClass(OptionalJWTEndpoint.class)
                .addClass(ScopedOptionalJWTEndpoint.class)
                .addAsWebInfResource(EmptyAsset.INSTANCE, ArchivePaths.create("beans.xml"));
    }

    @Test
    @RunAsClient
    public void jwtInjection() throws Exception {
        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/Token1.json"))
                .get("endp/verifyJwt")
                .then()
                .log().all()
                .statusCode(200);
    }

    @Test
    @RunAsClient
    public void jwtOptionalInjection() throws Exception {
        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/Token1.json"))
                .get("endp/verifyOptionalJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("Optional JWT is Present"));

        given()
                .log().all()
                .get("endp/verifyOptionalJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("Optional JWT is Empty"));
    }

    @Test
    @RunAsClient
    public void jwtProviderInjection() throws Exception {
        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/Token1.json"))
                .get("endp/verifyProviderJwt")
                .then()
                .log().all()
                .statusCode(200);
    }

    @Test
    @RunAsClient
    public void jwtScoped() throws Exception {
        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/Token1.json"))
                .get("endp/scoped/verifyJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("jdoe@example.com"));

        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/joe2-token.json"))
                .get("endp/scoped/verifyJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("jdoe2@example.com"));

        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/Token1.json"))
                .get("endp/scoped/verifyOptionalJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("jdoe@example.com"));

        // on ApplicationScoped Beans, the Optional will always have the same value (first one set).
        given()
                .log().all()
                .header(AUTHORIZATION, "Bearer " + generateTokenString("/joe2-token.json"))
                .get("endp/scoped/verifyOptionalJwt")
                .then()
                .log().all()
                .statusCode(200)
                .body(equalTo("jdoe@example.com"));
    }

    @Path("endp")
    @RequestScoped
    @Produces(MediaType.APPLICATION_JSON)
    public static class OptionalJWTEndpoint {
        @Inject
        private JsonWebToken jsonWebToken;
        @Inject
        private Optional<JsonWebToken> optionalJsonWebToken;
        @Inject
        private Provider<JsonWebToken> providerJsonWebToken;

        @GET
        @Path("/verifyJwt")
        @Produces(MediaType.APPLICATION_JSON)
        public Response verifyInjectedJwt() {
            // If NullJsonWebToken, this returns null
            if (jsonWebToken.getClaimNames() == null) {
                return Response.serverError().build();
            }

            return Response.ok().build();
        }

        @GET
        @Path("/verifyOptionalJwt")
        @Produces(MediaType.APPLICATION_JSON)
        public Response verifyInjectedOptionalJwt() {
            if (optionalJsonWebToken.isPresent()) {
                return Response.ok("Optional JWT is Present").build();
            }

            return Response.ok("Optional JWT is Empty").build();
        }

        @GET
        @Path("/verifyProviderJwt")
        @Produces(MediaType.APPLICATION_JSON)
        public Response verifyInjectedProviderJwt() {
            final JsonWebToken jsonWebToken = providerJsonWebToken.get();
            // If NullJsonWebToken, this returns null
            if (jsonWebToken.getClaimNames() == null) {
                return Response.serverError().build();
            }
            return Response.ok().build();
        }
    }

    @Path("endp/scoped")
    @ApplicationScoped
    @Produces(MediaType.APPLICATION_JSON)
    public static class ScopedOptionalJWTEndpoint {
        @Inject
        private JsonWebToken jsonWebToken;

        @Inject
        private Optional<JsonWebToken> optionalJsonWebToken;

        @GET
        @Path("/verifyJwt")
        @Produces(MediaType.APPLICATION_JSON)
        public Response verifyInjectedJwt() {
            // If NullJsonWebToken, this returns null
            if (jsonWebToken.getClaimNames() == null) {
                return Response.serverError().build();
            }

            return Response.ok(jsonWebToken.getName()).build();
        }

        @GET
        @Path("/verifyOptionalJwt")
        @Produces(MediaType.APPLICATION_JSON)
        public Response verifyInjectedOptionalJwt() {
            if (optionalJsonWebToken.isPresent()) {
                return Response.ok(optionalJsonWebToken.get().getName()).build();
            }

            return Response.serverError().build();
        }
    }
}
