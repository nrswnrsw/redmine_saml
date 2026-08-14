# Changelog

This file records notable user-facing changes to the maintained `nrswnrsw/redmine_saml` releases. Version 1.1.0 is the first maintained release based on the original `alphanodes/redmine_saml` 1.0.6 release and subsequent upstream work.

## [Unreleased]

### Added

- SAML confirmation for Redmine's Sudo Mode, on **Redmine 7.0 and later only**. When the Sudo Mode timeout expires and the current Redmine session was created by SAML, Redmine's local password prompt is replaced by a SAML confirmation button, both for the normal page prompt and for the modal shown by XHR requests. Redmine 7.0 enables Sudo Mode by default, so SAML-only users could otherwise no longer complete Sudo-protected actions.
- The Sudo `AuthnRequest` is built from the configured SAML settings of the initializer, used unchanged, so the plugin adds or removes no authentication condition of its own, including `ForceAuthn` and `IsPassive`. With a standard, static initializer it therefore carries the same authentication conditions as a normal SAML login. Whether the IdP prompts the user again remains an IdP policy decision. Request-scoped mechanisms are the documented exception: see the known limitation in the README.
- The Sudo transaction is correlated with the AuthnRequest ID through ruby-saml's `matches_request_id` (`InResponseTo`), a single-use RelayState nonce, a five minute expiry and a server-side single-use marker that is consumed atomically. A missing or unvalidated request ID fails the transaction instead of skipping the check.
- A callback that looks like a Sudo transaction but has no usable transaction behind it is rejected before the SAML Response is processed at all, so omniauth-saml never replaces the SAML NameID and SessionIndex of the current session with those of a Response the session did not ask for. If a Sudo callback is rejected later, in the controller, those identifiers are restored from a snapshot taken before the replacement.

### Backward compatibility

- No new initializer setting, no change to an existing initializer, and no new plugin setting. Existing `alphanodes/redmine_saml` 1.0.6 initializers keep working unchanged. An OmniAuth `:setup` endpoint configured in the initializer is left untouched and keeps its original semantics, and `idp_sso_service_url_runtime_params` is unchanged for normal login. The README documents that those two request-scoped mechanisms do not reach the Sudo `AuthnRequest`.
- No IdP configuration change, no additional ACS URL and no additional SAML provider registration. The existing `/auth/saml/callback` endpoint is reused.
- No database migration and no data conversion. The single-use marker uses the existing Redmine `tokens` table through the documented `Token.add_action` interface.
- The plugin directory name and plugin ID remain `redmine_saml`.
- On Redmine 6.0 and 6.1 the feature is not active in any form, including when `sudo_mode: true` is configured. The `ApplicationController` patch is not applied there, the Sudo `setup_phase` extension is not installed on the OmniAuth SAML strategy, no Sudo transaction can be started, and SAML callbacks never enter the Sudo path.
- Normal SAML login, logout, Single Logout, attribute mapping, on-the-fly creation, the `on_login` hook and the local Redmine password Sudo prompt are unchanged on every supported Redmine version.

### Security

- A Sudo re-authentication only succeeds when the pending transaction user, the signed-in Redmine user and the user resolved read-only from the SAML assertion are the same. A different IdP account fails the confirmation and never replaces the Redmine session.
- The Sudo callback never calls `handle_active_user`, `logged_user=`, `reset_session`, `start_user_session`, `update_last_login_on!`, the SAML `on_login` hook or on-the-fly user creation. A successful transaction only refreshes the Sudo Mode timestamp.
- A rejected transaction, including a replayed SAML Response, never falls back to the normal login path, never destroys the Redmine login session, and restores the SAML NameID and SessionIndex that were active before the transaction started.
- Return URLs are validated with Redmine's own back URL validation when the transaction starts and again when it completes. Starting a transaction requires a CSRF token and a POST; the existing callback CSRF exemption was not widened.
- The original request is not stored and not resubmitted after the IdP round trip.

## [1.1.1] - 2026-08-13

### Fixed

- Restored Single Logout for legacy initializers that do not set `single_logout_service_url`. When the setting is absent, the expected SLO `Destination` is derived from the required `assertion_consumer_service_url`, so a 1.0.6 initializer that omitted `single_logout_service_url` can keep working without adding that setting. An explicitly configured `single_logout_service_url` still takes precedence and its behavior is unchanged.
- The `Destination` fallback does not relax any existing SLO validation checks. The expected value is never inferred from the incoming request, and a message is still rejected when no expected `Destination` can be established.

### Maintenance

- Reorganized the internal SAML Redirect binding query handling, HTTP-POST signature validation, and authentication log formatting into separate classes without changing behavior.
- Extended regression test coverage for the `Destination` fallback, for the Redmine logout action, and for a settings helper test file that the plugin test task did not previously collect.
- Improved the 1.0.6 upgrade guidance in the README, including the Redmine version prerequisite, the fingerprint-only HTTP-Redirect Single Logout case, and post-upgrade verification steps.
- Constrained `omniauth-rails_csrf_protection` to version 1.0.2 or later while excluding 2.0.0, which breaks the OmniAuth request phase on Rails versions before 8.1.

Upgrading from `alphanodes/redmine_saml` 1.0.6 also involves the migration steps listed under 1.1.0 below.

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

1. Check the Redmine version first. Redmine 6.0 or later is required, and the requirement applies at the moment Redmine loads this plugin version. On Redmine 5.x, do not start Redmine with this plugin version in place; plan the work so that Redmine is already on 6.0 or later the first time it starts with it. Both updates can be done in the same maintenance window. On Redmine 6.0 or later, no Redmine upgrade is needed for this reason.
2. Back up the existing initializer and deployment configuration. This plugin adds no database migration of its own.
3. Preserve the existing initializer under `config/initializers/`.
4. Replace the code in `plugins/redmine_saml` with the maintained repository version, keeping the directory name `redmine_saml`.
5. Run `bundle install` from the Redmine root.
6. Run the standard plugin migration: `bundle exec rake redmine:plugins:migrate RAILS_ENV=production`.
7. If Single Logout is in use, make the initializer changes it needs now. When SLO uses the HTTP-Redirect binding and the initializer sets only `idp_cert_fingerprint`, replace it with the full IdP certificate in `idp_cert`; Redirect binding SLO cannot be validated from a fingerprint alone, while HTTP-POST binding SLO and SAML login keep working with a fingerprint. When `single_logout_service_url` is set explicitly, confirm that it matches the `/auth/saml/sls` endpoint.
8. Restart the Redmine application server.
9. If Single Logout is in use, update the Single Logout endpoint registered in the IdP. See the migration note below.
10. Verify the flows the deployment uses: SAML login, and SP-initiated or IdP-initiated Single Logout where applicable.

Additionals is not required for 1.1.0, but an existing Additionals installation does not need to be removed. Existing initializers do not need to add `idp_entity_id`; it remains optional, though recommended for stricter SLO Issuer validation.

#### IdP Single Logout endpoint migration

Handling of SAML messages sent by the IdP is consolidated on the plugin's own `/auth/saml/sls` endpoint, which validates the checks applicable to each message type before deleting a session: the signature, a present Issuer, and a matching `Destination` for both message types; the NameID and any SessionIndex for a `LogoutRequest`; and `InResponseTo` for a `LogoutResponse`. The Issuer is additionally compared with `idp_entity_id` when that optional setting is configured. 1.0.6 also reached SAML logout handling through `/logout`, and the legacy OmniAuth `/auth/saml/slo` and `/auth/saml/spslo` handlers were reachable as well. Those paths no longer process SAML logout messages sent by the IdP. Redmine's own `/logout` continues to handle normal logout and SP-initiated Single Logout.

This is an IdP-side configuration change; the Redmine ACS URL `/auth/saml/callback` is unaffected. If the Single Logout Service URL registered in the IdP is `/logout`, `/auth/saml/slo`, or `/auth/saml/spslo`, change it to `/auth/saml/sls`, keeping any relative URL root prefix. Redmine initializers that already point `single_logout_service_url` at `/auth/saml/sls` need no change. See the README for the full checklist.

### Known compatibility notes

- Redmine 5.x is not part of the 1.1.0 tested support range. Plugin metadata requires Redmine 6.0 or later.
- Existing users are looked up first by mapped login and then by mapped mail. Login and mail are not automatically synchronized, and mapped firstname/lastname changes are not automatically persisted on every SAML login unless a deployment's `on_login` hook explicitly saves them.
- A legacy `admin` mapping remains a no-op; 1.1.0 does not add IdP-driven administrator synchronization.
- `idp_entity_id` is optional for initializer compatibility but recommended for stronger SLO Issuer validation.

### Credits

Version 1.1.0 continues the work of [AlphaNodes GmbH](https://alphanodes.com/) and the original [alphanodes/redmine_saml](https://github.com/alphanodes/redmine_saml) authors and contributors. Current maintenance is provided in [nrswnrsw/redmine_saml](https://github.com/nrswnrsw/redmine_saml).
