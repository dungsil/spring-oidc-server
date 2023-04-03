package oidc.allinone

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.assertDoesNotThrow
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.test.web.reactive.server.WebTestClient
import kotlin.test.Test
import kotlin.test.assertEquals

@AutoConfigureMockMvc(printOnlyOnFailure = false)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OAuth2EndpointTest {

  @Autowired
  lateinit var http: WebTestClient

  @Autowired
  lateinit var client: RegisteredClientRepository

  @Autowired
  lateinit var om: ObjectMapper

  @Test
  fun authorize() {
    // @formatter:off
    http.post().uri("/oauth2/token")
      .contentType(MediaType.APPLICATION_FORM_URLENCODED)
      .bodyValue(buildString {
        append("grant_type=client_credentials")
        append("&client_id=local")
        append("&client_secret=secret")
      })
      .exchange()
        .expectStatus().isOk
        .expectBody()
          .consumeWith {
            val json = om.readValue(it.responseBody, HashMap::class.java)

            assertDoesNotThrow { SignedJWT.parse(json["access_token"] as String) }
            assertEquals("Bearer", json["token_type"])
            assertEquals(299, json["expires_in"])
          }
    // @formatter:on
  }
}
