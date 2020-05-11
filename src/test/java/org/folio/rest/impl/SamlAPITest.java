package org.folio.rest.impl;

import static io.restassured.RestAssured.given;
import static io.restassured.module.jsv.JsonSchemaValidator.matchesJsonSchemaInClasspath;
import static org.folio.util.Base64AwareXsdMatcher.matchesBase64XsdInClasspath;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.*;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.UUID;

import org.folio.rest.RestVerticle;
import org.folio.rest.jaxrs.model.SamlConfigRequest;
import org.folio.rest.jaxrs.model.SamlLogin;
import org.folio.rest.tools.client.test.HttpClientMock2;
import org.folio.util.TestingClasspathResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.pac4j.core.context.Pac4jConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.ls.LSResourceResolver;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

/**
 * @author rsass
 */
@RunWith(VertxUnitRunner.class)
public class SamlAPITest {
  private static final Logger log = LoggerFactory.getLogger(SamlAPITest.class);

  private static final Header TENANT_HEADER = new Header("X-Okapi-Tenant", "saml-test");
  private static final Header TOKEN_HEADER = new Header("X-Okapi-Token", "saml-test");
  private static final Header OKAPI_URL_HEADER = new Header("X-Okapi-Url", "http://localhost:9130");
  private static final Header JSON_CONTENT_TYPE_HEADER = new Header("Content-Type", "application/json");
  private static final String STRIPES_URL = "http://localhost:3000";

  public static final int PORT = 8081;
  private Vertx vertx;


  @Before
  public void setUp(TestContext context) throws Exception {
    vertx = Vertx.vertx();


    DeploymentOptions options = new DeploymentOptions()
      .setConfig(new JsonObject().put("http.port", PORT)
        .put(HttpClientMock2.MOCK_MODE, "true")
      );


    vertx.deployVerticle(new RestVerticle(),
      options,
      context.asyncAssertSuccess());

    RestAssured.port = PORT;
    RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

  }

  @After
  public void tearDown(TestContext context) throws Exception {
    vertx.close(context.asyncAssertSuccess());
  }

  @Test
  public void checkEndpointTests() {


    // bad
    given()
      .get("/saml/check")
      .then()
      .statusCode(400);

    // good
    given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .get("/saml/check")
      .then()
      .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
      .body("active", equalTo(Boolean.TRUE))
      .statusCode(200);
    
//  // with no csrf token cookie
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .get("/saml/check")
//    .then()
//    .statusCode(401);
//  
//  // login
//  String csrfTokenCookie = given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(JSON_CONTENT_TYPE_HEADER)
//    .body("{\"stripesUrl\":\"" + STRIPES_URL + "\"}")
//    .post("/saml/login")
//    .then()
//    .log().all()
//    .extract().cookie(Pac4jConstants.CSRF_TOKEN);
//
//  // with csrf token cookie but no header or param
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .statusCode(401);
//  
//  // valid, as param
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .formParam(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
//    .body("active", equalTo(Boolean.TRUE))
//    .statusCode(200);  
//  
//  // valid, as header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
//    .body("active", equalTo(Boolean.TRUE))
//    .statusCode(200);
//  
//  // valid, as param and header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .formParam(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
//    .body("active", equalTo(Boolean.TRUE))
//    .statusCode(200); 
//  
//  // invalid, as param
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .statusCode(401); 
//  
//  // invalid, as header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .statusCode(401);
//  
//  // invalid, as param and header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .statusCode(401); 
//  
//  // valid param, invalid header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .formParam(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
//    .body("active", equalTo(Boolean.TRUE))
//    .statusCode(200); 
//  
//  // invalid param, valid header
//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//    .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//    .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//    .get("/saml/check")
//    .then()
//    .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlCheck.json"))
//    .body("active", equalTo(Boolean.TRUE))
//    .statusCode(200);

  }

  @Test
  public void loginEndpointTests() {

    // empty body
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .header(JSON_CONTENT_TYPE_HEADER)
//      .post("/saml/login")
//      .then()
//      .statusCode(400);

    // good
    ExtractableResponse<Response> loginResp = given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .header(JSON_CONTENT_TYPE_HEADER)
      .body("{\"stripesUrl\":\"" + STRIPES_URL + "\"}")
      .post("/saml/login")
      .then()
      .log().all()
      .contentType(ContentType.JSON)
      .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlLogin.json"))
      .body("bindingMethod", equalTo("POST"))
      .body("relayState", startsWith(STRIPES_URL+"?csrfToken="))
      .statusCode(200)
      .extract();
    
    System.out.println(loginResp.body().asString());
    SamlLogin json = loginResp.body().as(SamlLogin.class);
    given()
      .formParam("SAMLRequest", json.getSamlRequest())
      .formParam("RelayState", json.getRelayState())
      .log().all()
      .post(json.getLocation())      
      .then()
      .log().all();

  }

  @Test
  public void regenerateEndpointTests() {


    LSResourceResolver resolver = new TestingClasspathResolver("schemas/");

    given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .get("/saml/regenerate")
      .then()
      .contentType(ContentType.JSON)
      .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlRegenerateResponse.json"))
      .body("fileContent", matchesBase64XsdInClasspath("schemas/saml-schema-metadata-2.0.xsd", resolver))
      .statusCode(200);

  }

  @Test
  public void callbackEndpointTests() throws IOException {


    final String testPath = "/test/path";

//  given()
//    .header(TENANT_HEADER)
//    .header(TOKEN_HEADER)
//    .header(OKAPI_URL_HEADER)
//    .formParam("SAMLResponse", "saml-response")
//    .formParam("RelayState", STRIPES_URL + testPath)
//    .post("/saml/callback")
//    .then()
//    .statusCode(302)
//    .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
//    .header("x-okapi-token", "saml-token")
//    .cookie("ssoToken", "saml-token"); 
    
    // with no csrf token cookie
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .post("/saml/callback")
//      .then()
//      .statusCode(401);
    
    // login
    String csrfTokenCookie = given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .header(JSON_CONTENT_TYPE_HEADER)
      .body("{\"stripesUrl\":\"" + STRIPES_URL + "\"}")
      .post("/saml/login")
      .then()
      .log().all()
      .extract().cookie("csrfToken");
 
    
    
    // with csrf token cookie but no header or param
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(401);
    
    // valid, as param
    given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .formParam("SAMLResponse", "saml-response")
      .formParam("RelayState", STRIPES_URL + testPath + "?csrfToken=" + csrfTokenCookie)
      .cookie("csrfToken", csrfTokenCookie + "; Path=/; Domain=localhost")
      .post("/saml/callback")
      .then()
      .log().all()
      .statusCode(302)
      .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
      .header("x-okapi-token", "saml-token")
      .cookie("ssoToken", "saml-token");    
    
    // valid, as header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(302)
//      .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
//      .header("x-okapi-token", "saml-token")
//      .cookie("ssoToken", "saml-token");
//    
//    // valid, as param and header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .formParam(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(302)
//      .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
//      .header("x-okapi-token", "saml-token")
//      .cookie("ssoToken", "saml-token");    
//    
//    // invalid, as param
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(401);   
//    
//    // invalid, as header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(401); 
//    
//    // invalid, as param and header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(401);    
//    
//    // valid param, invalid header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .header(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .formParam(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(302)
//      .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
//      .header("x-okapi-token", "saml-token")
//      .cookie("ssoToken", "saml-token");   
//    
//    // invalid param, valid header
//    given()
//      .header(TENANT_HEADER)
//      .header(TOKEN_HEADER)
//      .header(OKAPI_URL_HEADER)
//      .header(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie)
//      .formParam("SAMLResponse", "saml-response")
//      .formParam("RelayState", STRIPES_URL + testPath)
//      .formParam(Pac4jConstants.CSRF_TOKEN, UUID.randomUUID().toString())
//      .cookie(Pac4jConstants.CSRF_TOKEN, csrfTokenCookie + "; Path=/; Domain=localhost")
//      .post("/saml/callback")
//      .then()
//      .statusCode(302)
//      .header("Location", containsString(URLEncoder.encode(testPath, "UTF-8")))
//      .header("x-okapi-token", "saml-token")
//      .cookie("ssoToken", "saml-token");       
    
  }

  @Test
  public void getConfigurationEndpoint() {

    // GET
    given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .header(JSON_CONTENT_TYPE_HEADER)
      .get("/saml/configuration")
      .then()
      .statusCode(200)
      .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlConfig.json"))
      .body("idpUrl", equalTo("https://idp.ssocircle.com"))
      .body("samlBinding", equalTo("POST"))
      .body("metadataInvalidated", equalTo(Boolean.FALSE));
  }

  @Ignore("2 external http servers should be mocked")
  @Test
  public void putConfigurationEndpoint() {


    SamlConfigRequest samlConfigRequest = new SamlConfigRequest()
      .withIdpUrl(URI.create("http://localhost"))
      .withSamlAttribute("UserID")
      .withSamlBinding(SamlConfigRequest.SamlBinding.POST)
      .withUserProperty("externalSystemId")
      .withOkapiUrl(URI.create("http://localhost:9130"));

    String jsonString = Json.encode(samlConfigRequest);

    // PUT
    given()
      .header(TENANT_HEADER)
      .header(TOKEN_HEADER)
      .header(OKAPI_URL_HEADER)
      .header(JSON_CONTENT_TYPE_HEADER)
      .body(jsonString)
      .put("/saml/configuration")
      .then()
      .statusCode(200)
      .body(matchesJsonSchemaInClasspath("ramls/schemas/SamlConfig.json"));

  }

  @Test
  public void healthEndpointTests() {

    // good
    given()
      .get("/admin/health")
      .then()
      .statusCode(200);

  }

}
