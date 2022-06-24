package org.acme;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.http.base.cookie.CookieHandler;
import org.apache.camel.http.base.cookie.InstanceCookieHandler;
import org.apache.camel.support.CamelContextHelper;
import org.jboss.logging.Logger;

import javax.inject.Named;
import javax.inject.Singleton;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.util.UUID;

public class Routes extends RouteBuilder {

    private static final Logger LOG = Logger.getLogger(Routes.class.getName());

    @Singleton
    @Named("cookieHandler")
    public CookieHandler cookieHandler() {
        CookieHandler handler = new InstanceCookieHandler();
        handler.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        return handler;
    }

    @Override
    public void configure() throws Exception {
        // Start a session by authenticating with the fake service
        from("timer:login?repeatCount=1")
                .log("Performing login...")
                .to("http://localhost:{{quarkus.http.port}}/login?username=admin&password=2s3cr3t&cookieHandler=#cookieHandler&httpClient.cookieSpec=standard")
                .log("Got cookie values: ${header.Set-Cookie}");

        // Access restricted content by sending the sessionId cookie set from the above route
        from("timer:getSecretContent?delay=1500&period=5s")
                .log("Accessing restricted content...")
                .to("http://localhost:{{quarkus.http.port}}/test?cookieHandler=#cookieHandler&httpClient.cookieSpec=standard")
                .log("Got response: ${body}");

        from("platform-http:/login")
                .process(new Processor() {
                    @Override
                    public void process(Exchange exchange) throws Exception {
                        Message message = exchange.getMessage();
                        String username = message.getHeader("username", String.class);
                        String password = message.getHeader("password", String.class);

                        if (username.equals("admin") && password.equals("2s3cr3t")) {
                            message.setHeader("Set-Cookie", "sessionId=" + UUID.randomUUID());
                            message.setHeader(Exchange.HTTP_RESPONSE_CODE, 200);
                        } else {
                            message.setHeader(Exchange.HTTP_RESPONSE_CODE, 401);
                        }
                    }
                });


        from("platform-http:/test")
                .process(new Processor() {
                    @Override
                    public void process(Exchange exchange) throws Exception {
                        // Output content of the cookie handler
                        CookieHandler handler = CamelContextHelper.lookup(exchange.getContext(), "cookieHandler", CookieHandler.class);
                        CookieStore cookieStore = handler.getCookieStore(exchange);
                        cookieStore.getCookies().forEach(cookie -> {
                            LOG.infof("Cookie %s = %s", cookie.getName(), cookie.getValue());
                        });

                        // Perform some crude session handling
                        Message message = exchange.getMessage();
                        String cookie = message.getHeader("Cookie", String.class);
                        if (cookie.contains("sessionId")) {
                            message.setBody("Session found - Here's your secret content...");
                            message.setHeader(Exchange.HTTP_RESPONSE_CODE, 200);
                        } else {
                            message.setBody("Session not found - permission denied");
                            message.setHeader(Exchange.HTTP_RESPONSE_CODE, 403);
                        }
                    }
                });
    }
}
