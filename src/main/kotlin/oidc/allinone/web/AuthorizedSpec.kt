package oidc.allinone.web

import jakarta.validation.constraints.NotEmpty
import java.util.UUID

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.05
 */
data class AuthorizedSpec(
  val code: String? = null,
  val state: String? = null,
  val error: String? = null,
)
