package io.smallrye.jwt.tck;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import jakarta.enterprise.context.RequestScoped;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ArchivePaths;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestApplication extends Arquillian {
    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap
                .create(WebArchive.class)
                .addClass(TestServlet.class)
                .addClass(RestApplication.class)
                .addClass(TestEndpoint.class)
                .addAsWebInfResource(EmptyAsset.INSTANCE, ArchivePaths.create("beans.xml"));
    }

    @Test
    @RunAsClient
    public void servlet() {
        String uri = baseURL.toExternalForm() + "servlet";
        WebTarget echoEndpointTarget = ClientBuilder.newClient().target(uri);
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
    }

    @Test
    @RunAsClient
    public void rest() {
        String uri = baseURL.toExternalForm() + "rest";
        WebTarget echoEndpointTarget = ClientBuilder.newClient().target(uri);
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
    }

    @WebServlet(urlPatterns = "/servlet")
    public static class TestServlet extends HttpServlet {
        @Override
        protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
            resp.getWriter().write("hello");
        }
    }

    @ApplicationPath("/rest")
    public static class RestApplication extends jakarta.ws.rs.core.Application {
        @Override
        public Set<Class<?>> getClasses() {
            final HashSet<Class<?>> classes = new HashSet<>();
            classes.add(TestEndpoint.class);
            return classes;
        }
    }

    @RequestScoped
    @Path("/")
    public static class TestEndpoint {
        @GET
        public String hello() {
            return "hello";
        }
    }
}
