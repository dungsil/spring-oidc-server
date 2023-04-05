package oidc.allinone.web

import oidc.allinone.global.AppEnvironment
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import java.net.URI

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.05
 */
@RestController
@RequestMapping("/authorized")
class AuthorizedController(
  private val http: RestTemplate,
  private val env: AppEnvironment,
) {
  private val log = LoggerFactory.getLogger(AuthorizedController::class.java)

  @GetMapping
  fun authorized(@RequestParam spec: AuthorizedSpec): AuthorizedSpec {
    log.debug("OAuth2 spec: (code={}, state={}, error={})", spec.code, spec.state, spec.error)

    return spec
  }
}
