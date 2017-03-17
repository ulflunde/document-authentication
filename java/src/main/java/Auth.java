import static spark.Spark.*;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Properties;

import com.signicat.services.client.ScResponseException;
import com.signicat.services.client.ScSecurityException;
import com.signicat.services.client.saml.SamlFacade;
import com.signicat.services.client.saml.SamlResponseData;

public class Auth {

    public static void main(String[] args) {

        get("/", (request, response) -> {

            String target = request.url() + "verify";
            String targetUrlEncoded = urlEncode(target);
            String authenticationUrl = "https://preprod.signicat.com/std/method/shared/?id=nbid:demo:nb&target=" + targetUrlEncoded;
            response.redirect(authenticationUrl);
            return null;
        });

        post("/verify", (request, response) -> {

            String nationalId = null;
            String assertion = request.queryParams("SAMLResponse");
            if (assertion != null && assertion.length() > 0) {

                Properties configuration = new Properties();
                configuration.setProperty("debug", "false");

                // The name of the certificate we trust.
                // IMPORTANT! This must be changed when moving from test to
                // production.
                boolean useTestEnvironment = true;
                if (useTestEnvironment) {
                    configuration.setProperty("asserting.party.certificate.subject.dn",
                            "CN=test.signicat.com/std, OU=Signicat, O=Signicat, L=Trondheim, ST=Norway, C=NO");
                } else {
                    configuration.setProperty("asserting.party.certificate.subject.dn",
                            "CN=id.signicat.com/std, OU=Signicat, O=Signicat, L=Trondheim, ST=Norway, C=NO");
                }

                // Creates the SamlFacade object that will be used to parse SAML
                // responses
                SamlFacade samlFacade = new SamlFacade(configuration);
                try {
                    // Parse and validate the SAML Request
                    SamlResponseData samlResponseData = samlFacade.readSamlResponse(assertion, new URL(request.url()));

                    for (SamlResponseData.Attribute attribute : samlResponseData.getAttributes()) {
                        if (attribute.getName().equals("no.fnr")) {
                            nationalId = (String) attribute.getValue();
                            System.out.println(nationalId);
                        }
                    }

                } catch (ScResponseException e) {
                    System.out.println("ERROR: The user was not authenticated: " + e.getMessage());
                } catch (ScSecurityException e) {
                    System.out.println("ERROR: The login was aborted. Technical message: " + e.getMessage());
                } catch (MalformedURLException e) {
                    System.out.println("ERROR: Failed to understand recipient URL. " + e.getMessage());
                }
            }

            if (nationalId != null) {

                // Demo code for illustration purposes.
                // You are not required nor encouraged to use the national
                // identity number in your cookies.
                response.cookie("nationalid", nationalId, 3600, true);
                response.redirect("/granted");

            } else {
                response.redirect("/denied");
            }
            return null;
        });

        get("/granted", (request, response) -> {
            String nationalId = request.cookie("nationalid");
            System.out.println(nationalId);
            response.type("text/plain");
            return "Access granted";
        });

        get("/denied", (request, response) -> {
            response.type("text/plain");
            response.status(401);
            return "Access denied";
        });

    }

    public static String urlEncode(String s) {

        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

}
