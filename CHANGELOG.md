# Changelog

This file records notable user-facing changes to the maintained `nrswnrsw/redmine_saml` releases. Version 1.1.0 is the first maintained release based on the original `alphanodes/redmine_saml` 1.0.6 release and subsequent upstream work.

## [1.1.0] - 2026-08-12

### Backward compatibility

- Existing `alphanodes/redmine_saml` initializers can normally be used unchanged on the supported Redmine versions. No new required SAML setting was added.
- The plugin directory name remains `redmine_saml`.
- Additionals is no longer required for a new installation. Existing Redmine installations can keep Additionals installed; removing it is not an upgrade requirement.
- Existing attribute mapping semantics are preserved. The required mappings remain `login`, `mail`, `firstname`, and `lastname`; a legacy `admin` mapping is still accepted but is not used to promote or demote administrators, and automatic existing-user attribute synchronization was not introduced.

### Added

- Tested support for the following Redmine and Ruby combinations, each with PostgreSQL and MySQL:
  - Redmine 6.0 with Ruby 3.1, 3.2, and 3.3.
  - Redmine 6.1 with Ruby 3.2, 3.3, and 3.4.
  - Redmine 7.0 with Ruby 3.2, 3.3, 3.4, and 4.0.
- A real browser SAML E2E workflow using Redmine 7, Ruby 3.4, PostgreSQL, Keycloak 26.x, Playwright, and Chromium. It covers SAML login and the complete SP-initiated Single Logout flow, including termination of both the Redmine and Keycloak sessions.
- Secure SP-initiated and IdP-initiated Single Logout handling for signed LogoutRequest and LogoutResponse messages.
- Optional `idp_slo_response_service_url` support for sending IdP-initiated LogoutResponses to a dedicated configured endpoint, with fallback to `idp_slo_service_url`.
- Optional `idp_entity_id` validation for strict SLO Issuer matching.

### Changed

- Removed Additionals as a required plugin dependency and replaced Additionals-specific settings helpers with Redmine standard view/form helpers.
- Added `slim-rails` as a direct dependency so Slim view support no longer relies on another plugin.
- Aligned successful SAML callbacks with Redmine's standard active-user authentication lifecycle, including Sudo Mode timestamp updates, while preserving SAML session data needed for logout.
- SAML callbacks now use Redmine's inactive-user handling semantics and refuse locked or pending users without creating an authenticated session.
- SP-initiated SLO now ends the Redmine local session before redirecting to the IdP. A later IdP or LogoutResponse failure does not undo the local logout.
- Cross-site HTTP-POST SLO now works when the main Redmine `SameSite=Lax` session cookie is not sent, using dedicated encrypted `SameSite=None; Secure` context cookies bound to a short-lived one-time SLO transaction Token for SP-initiated responses and to the exact Redmine session Token for IdP-initiated requests.
- The existing session-based SLO path remains primary; the dedicated cookie and Token path is only a fallback for cross-site HTTP-POST messages.
- Existing HTTP deployments and HTTP-Redirect Binding keep their prior session-based behavior; the dedicated cross-site POST fallback is HTTPS-only. Existing initializer behavior remains compatible.
- Preserved legacy attribute mapping behavior with explicit regression coverage. See the README for existing-user persistence and `on_login` hook details.
- Updated the README, sample initializer, repository metadata, support matrix, installation instructions, and SAML/SLO configuration guidance for the maintained repository.

### Security

- Blocked direct SAML login and callback authentication when the plugin's `saml_enabled` setting is disabled, including IdP-initiated callback attempts.
- Rejects unsigned, invalid, or context-mismatched SLO messages without deleting a Redmine session. Validation covers configured certificates, Issuer, Destination, NameID, SessionIndex, and SP LogoutRequest transaction matching (`InResponseTo`) as applicable.
- Preserves the original encoded HTTP-Redirect query values for signature verification and rejects duplicate signed query parameters.
- Supports fingerprint-only HTTP-POST SLO by verifying the embedded certificate, fingerprint, XML signature, and configured certificate-expiration policy.
- Requires a full IdP public certificate (`idp_cert` or an appropriate `idp_cert_multi`) for HTTP-Redirect SLO query-signature verification. Fingerprint-only HTTP-Redirect SLO is rejected rather than bypassing validation.
- Prevents inactive Redmine users from authenticating through SAML callbacks.
- Prevents SP private keys and ruby-saml Settings objects from being included in the two legacy INFO AuthHash logs while preserving logged SAML Response XML, attributes, NameID, and SessionIndex troubleshooting data.
- Redacts top-level SP `private_key` values and signing/encryption private keys under `sp_cert_multi` as `[REDACTED]` in the administrative SAML settings information tab. Public certificates, fingerprints, endpoints, and mapping data remain visible.
- Established dependency security floors of `omniauth-saml >= 2.2.4` and `ruby-saml >= 1.18.1`.

### Fixed

- Added Redmine 7 and Rails 8.1 compatibility, including explicit external redirects only to administrator-configured IdP SSO/SLO endpoints.
- Corrected `replace_redmine_login` to use a CSRF-protected POST bridge through the OmniAuth request phase instead of redirecting directly to the IdP, producing a standard SP-initiated AuthnRequest. The configured IdP SSO URL must accept SP-initiated AuthnRequests.
- Fixed the plugin settings screen so it renders and saves correctly without Additionals.
- Corrected IdP LogoutResponse URL query separators when `idp_slo_response_service_url` and `idp_slo_service_url` differ in whether they contain a query string. The workaround uses a request-local ruby-saml Settings copy and does not modify global settings or monkey-patch ruby-saml.
- Preserved IdP-specific raw percent encoding, including ADFS-compatible encoding differences, when validating HTTP-Redirect LogoutRequest and LogoutResponse signatures.
- Restored the legacy SLO ERROR markers and the successful SP LogoutResponse `Delete session for '<login>'` INFO marker while retaining detailed rejection warnings and the local-logout-first design.
- Corrected misleading sample configuration: HTTPS/example-domain URLs, mutually exclusive certificate alternatives, SHA-256 fingerprint guidance, the `lastname` mapping typo, and the unsupported active `admin` mapping example.
- Prevented private keys from being exposed by the SAML settings information tab while preserving its troubleshooting value.

### SLO certificate compatibility

- Fingerprint-only SAML login remains supported.
- Fingerprint-only HTTP-POST SLO is supported when the signed XML contains the certificate required for fingerprint and signature validation.
- HTTP-Redirect SLO requires a configured full IdP public certificate. Fingerprint-only HTTP-Redirect SLO is safely rejected.

### Upgrade notes for 1.0.6 users

1. Preserve the existing initializer under `config/initializers/`.
2. Replace the code in `plugins/redmine_saml` with the maintained repository version, keeping the directory name `redmine_saml`.
3. Run `bundle install` from the Redmine root.
4. Run the standard plugin migration: `bundle exec rake redmine:plugins:migrate RAILS_ENV=production`.
5. Restart the Redmine application server.

Additionals is not required for 1.1.0, but an existing Additionals installation does not need to be removed. Existing initializers do not need to add `idp_entity_id`; it remains optional, though recommended for stricter SLO Issuer validation.

### Known compatibility notes

- Redmine 5.x is not part of the 1.1.0 tested support range. Plugin metadata requires Redmine 6.0 or later.
- Existing users are looked up first by mapped login and then by mapped mail. Login and mail are not automatically synchronized, and mapped firstname/lastname changes are not automatically persisted on every SAML login unless a deployment's `on_login` hook explicitly saves them.
- A legacy `admin` mapping remains a no-op; 1.1.0 does not add IdP-driven administrator synchronization.
- `idp_entity_id` is optional for initializer compatibility but recommended for stronger SLO Issuer validation.

### Credits

Version 1.1.0 continues the work of [AlphaNodes GmbH](https://alphanodes.com/) and the original [alphanodes/redmine_saml](https://github.com/alphanodes/redmine_saml) authors and contributors. Current maintenance is provided in [nrswnrsw/redmine_saml](https://github.com/nrswnrsw/redmine_saml).
