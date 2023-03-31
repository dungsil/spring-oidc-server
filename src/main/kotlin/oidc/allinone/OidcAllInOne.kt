package oidc.allinone

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.03.31
 */
@SpringBootApplication
class OidcAllInOne

fun main(args: Array<String>) {
  runApplication<OidcAllInOne>(*args)
}
