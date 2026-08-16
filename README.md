# Redmine OmniAuth SAML plugin

[![Tests](https://github.com/nrswnrsw/redmine_saml/actions/workflows/tests.yml/badge.svg)](https://github.com/nrswnrsw/redmine_saml/actions/workflows/tests.yml)
[![Run Linters](https://github.com/nrswnrsw/redmine_saml/actions/workflows/linters.yml/badge.svg)](https://github.com/nrswnrsw/redmine_saml/actions/workflows/linters.yml)
[![Run Brakeman](https://github.com/nrswnrsw/redmine_saml/actions/workflows/brakeman.yml/badge.svg)](https://github.com/nrswnrsw/redmine_saml/actions/workflows/brakeman.yml)
[![SAML E2E](https://github.com/nrswnrsw/redmine_saml/actions/workflows/e2e.yml/badge.svg)](https://github.com/nrswnrsw/redmine_saml/actions/workflows/e2e.yml)

This plugin adds SAML authentication support to [Redmine](https://www.redmine.org). It is built on the [OmniAuth authentication framework](https://github.com/omniauth/omniauth) and [omniauth-saml](https://github.com/omniauth/omniauth-saml).

The current maintenance goal is to support Redmine 7 while preserving compatibility with supported Redmine 6 releases and existing `alphanodes/redmine_saml` configurations.

## Tested versions and requirements

The GitHub Actions test matrix verifies every listed Ruby version with both PostgreSQL and MySQL:

| Redmine | Tested Ruby versions | Tested databases |
| --- | --- | --- |
| 6.0 | 3.1, 3.2, 3.3 | PostgreSQL, MySQL |
| 6.1 | 3.2, 3.3, 3.4 | PostgreSQL, MySQL |
| 7.0 | 3.2, 3.3, 3.4, 4.0 | PostgreSQL, MySQL |

The real SAML E2E workflow separately tests Redmine 7.0 with Ruby 3.4, PostgreSQL, Keycloak 26.x, Playwright, and Chromium. It exercises a real SAML login and SP-initiated Single Logout flow.

The plugin metadata requires Redmine 6.0 or later, but tested support is limited to the combinations above.

The plugin directly declares its runtime dependencies, including `slim-rails`. Additionals is no longer required; existing installations may keep it installed.

Security-sensitive dependency floors are `omniauth-saml >= 2.2.4` and `ruby-saml >= 1.18.1`. Run `bundle install` after every installation or upgrade so that these requirements are resolved.

## Fresh installation

See the [Redmine plugin installation guide](https://www.redmine.org/projects/redmine/wiki/plugins) for general plugin instructions.

The plugin directory name must remain exactly `redmine_saml`.

```shell
export REDMINE_ROOT=/path/to/redmine
cd "$REDMINE_ROOT"

git clone https://github.com/nrswnrsw/redmine_saml.git plugins/redmine_saml
bundle install
bundle exec rake redmine:plugins:migrate RAILS_ENV=production

cp plugins/redmine_saml/contrib/sample_saml_initializers.rb config/initializers/saml.rb
vi config/initializers/saml.rb
```

Replace every placeholder in the initializer with values from your Redmine deployment and IdP, then restart the Redmine application server.

Finally, enable and configure the plugin under **Administration > Plugins > Redmine SAML > Configure**.

## Upgrading from `alphanodes/redmine_saml`

Existing AlphaNodes users can normally keep their current initializer unchanged. No new SAML setting is required solely to move to this maintained repository. One case is an exception: a fingerprint-only initializer that has to validate HTTP-Redirect binding Single Logout. Step 7 below explains how to tell whether it applies.

Before starting, back up the existing SAML initializer under `config/initializers/` and the rest of your deployment configuration. This plugin adds no database migration of its own, so no data conversion is involved. When Redmine itself is upgraded at the same time, follow the normal Redmine upgrade backup procedure for that part.

1. Check the Redmine version first. This plugin requires Redmine 6.0 or later, and that requirement applies at the moment Redmine loads it. If Redmine is still on 5.x, do not start Redmine with the current plugin version in place: plan the work so that Redmine is already on 6.0 or later the first time it starts with this plugin version. Updating Redmine and the plugin in the same maintenance window is fine. On Redmine 6.0 or later, no Redmine upgrade is needed for this reason.
2. Preserve the existing file under `config/initializers/` and any deployment-specific configuration.
3. Replace the code in `plugins/redmine_saml` with the current `nrswnrsw/redmine_saml` version.
4. Keep the directory name exactly `redmine_saml`.
5. Run `bundle install` from the Redmine root.
6. Run `bundle exec rake redmine:plugins:migrate RAILS_ENV=production`.
7. If Single Logout is in use, make the initializer changes it needs before restarting: follow [Switching from a fingerprint-only initializer](#switching-from-a-fingerprint-only-initializer) when that case applies, and confirm that an explicitly configured `single_logout_service_url` matches the `/auth/saml/sls` endpoint.
8. Restart the Redmine application server.
9. If Single Logout is in use, update the Single Logout endpoint registered in the IdP as described below.
10. Verify the result as described in [Verify after upgrading](#verify-after-upgrading).

Additionals is no longer required by this plugin. It does not need to be removed from an existing Redmine installation. This plugin itself has no Additionals dependency, so an administrator may remove Additionals once no other plugin in the installation needs it.

Optional settings such as `idp_entity_id` can strengthen validation, but they are not migration requirements for existing initializers.

If Single Logout is in use, check the Single Logout endpoint registered in the IdP as well. 1.0.6 accepted SAML logout messages on several paths; `/auth/saml/sls` is now the only IdP-facing endpoint that processes SAML `LogoutRequest` and `LogoutResponse` messages. Redmine's own `/logout` continues to handle normal logout and SP-initiated Single Logout. See [Migrating the IdP Single Logout endpoint from 1.0.6](#migrating-the-idp-single-logout-endpoint-from-106).

### Switching from a fingerprint-only initializer

This applies only when **all** of the following are true:

- Single Logout is in use.
- SLO messages are exchanged over the HTTP-Redirect binding.
- The initializer sets `idp_cert_fingerprint` without `idp_cert` or `idp_cert_multi`.

An HTTP-Redirect binding signature is verified over the query string and cannot be checked from a fingerprint alone, so those SLO messages are rejected. Redirect binding SLO therefore needs the IdP certificate itself.

If Single Logout is not used, or SLO uses only the HTTP-POST binding, the existing fingerprint setting can stay exactly as it is. SAML login is also unaffected and keeps working with a fingerprint-only configuration.

When the case applies:

1. Export the public certificate that the IdP uses to sign SAML messages.
2. Set it as `idp_cert` in the initializer, in PEM form.
3. Remove `idp_cert_fingerprint` and `idp_cert_fingerprint_algorithm`. They are alternatives to `idp_cert` rather than additions, and `idp_cert` takes precedence when both are present.

Then return to the upgrade procedure above and continue from the restart step; this change needs no separate restart of its own.

See [Certificates, fingerprints, and SLO bindings](#certificates-fingerprints-and-slo-bindings) for the full description of the certificate options.

### Verify after upgrading

Check only the flows the deployment actually uses:

1. Sign in to Redmine through SAML.
2. If SP-initiated Single Logout is used, sign out from Redmine and confirm that the IdP session ends as well.
3. If IdP-initiated Single Logout is used, sign out at the IdP and confirm that the Redmine session ends as well.

If a step fails, check the Redmine production log for the SAML login and logout entries written during that attempt.

## SAML configuration

Copy and edit the [sample initializer](contrib/sample_saml_initializers.rb). The most important login settings are:

- `assertion_consumer_service_url`: public Redmine SAML callback URL.
- `idp_sso_service_url`: IdP Single Sign-On endpoint.
- `idp_cert`: IdP public signing certificate used to verify SAML messages. A full certificate is recommended.
- `attribute_mapping`: paths used to read Redmine user attributes from the OmniAuth SAML result.

For the complete set of lower-level OmniAuth SAML options, see the [omniauth-saml options documentation](https://github.com/omniauth/omniauth-saml#options).

When `replace_redmine_login` is enabled, login still uses OmniAuth's standard SP-initiated request phase and generates a SAML AuthnRequest through a CSRF-protected POST bridge. `idp_sso_service_url` must therefore be a normal SAML SSO endpoint that accepts SP-initiated AuthnRequests. No new setting key or initializer schema change is required.

Legacy configurations that specify an IdP-initiated-only URL should verify this endpoint. For example, Keycloak's `/protocol/saml/clients/<client>` URL is an IdP-initiated deep link; use the standard `/protocol/saml` endpoint for SP-initiated requests instead.

### Attribute mapping and existing users

These four mappings are required:

- `login`
- `mail`
- `firstname`
- `lastname`

With on-the-fly creation enabled, all four values are saved when the plugin creates a new Redmine user.

For an existing user, the plugin first searches by mapped login and then by mapped mail address. It does not automatically synchronize login or mail on every SAML login. Mapped firstname and lastname are available during the login request, but the plugin itself does not persist those changes for an existing user.

The `on_login` hook runs after firstname and lastname have been mapped. A deployment-specific hook can inspect those values and explicitly save the user if attribute synchronization is desired.

`admin` is not a required mapping. A legacy initializer may still contain an `admin` entry, but the current plugin does not use it to promote or demote Redmine administrators.

### Single Logout settings

- `single_logout_service_url`: public Redmine SLS endpoint (`/auth/saml/sls`). It must match the SAML message `Destination` exactly.
- `idp_slo_service_url`: IdP Single Logout Service endpoint used for SAML logout messages.
- `idp_slo_response_service_url`: optional endpoint for the LogoutResponse sent after an IdP-initiated LogoutRequest. It falls back to `idp_slo_service_url` when omitted.
- `idp_entity_id`: optional but recommended IdP entity ID. When configured, the plugin compares it with the Issuer of SLO messages.
- `signout_url`: legacy IdP sign-out URL used for failed-login cleanup and as the existing configuration gate for SP-initiated SLO. The SAML LogoutRequest itself is sent to `idp_slo_service_url`.
- `name_identifier_value`: Redmine user field used as the logout NameID when session SAML data is unavailable.

#### SP-initiated Single Logout

When an authenticated SAML user signs out through Redmine, the plugin creates a LogoutRequest and redirects the browser to the configured IdP. The Redmine local session is ended before that redirect. If the IdP request or response later fails, the local Redmine logout remains in effect.

#### IdP-initiated Single Logout

IdP-initiated logout is accepted only for an active SAML session. The plugin validates the signed LogoutRequest and its SAML context before ending the local Redmine session and returning a LogoutResponse to the configured IdP endpoint. An unvalidated external request does not delete the Redmine session.

On HTTPS deployments, cross-site HTTP-POST SLO can use a dedicated, short-lived `SameSite=None; Secure` cookie fallback. This fallback is limited to SLO and does not globally change the normal Redmine session cookie settings. HTTP deployments do not use the fallback and retain the existing session-based path; HTTPS is not a new general requirement for SAML login.

#### Migrating the IdP Single Logout endpoint from 1.0.6

**This step changes a setting in the IdP administration UI, not in Redmine.** The Redmine Assertion Consumer Service (ACS) URL `/auth/saml/callback` is a different endpoint and must be left unchanged.

The Single Logout Service endpoint of this plugin is:

```
/auth/saml/sls
```

For a normal root deployment:

```
https://redmine.example.com/auth/saml/sls
```

When Redmine runs under a relative URL root, keep that prefix:

```
https://redmine.example.com/redmine/auth/saml/sls
```

1.0.6 could reach SAML logout handling through several paths. `/auth/saml/sls` is now the only endpoint that processes SAML `LogoutRequest` and `LogoutResponse` messages sent by the IdP. If the IdP is still configured with one of the following, IdP-initiated Single Logout will no longer be processed and the endpoint has to be updated:

| Endpoint registered in the IdP | Replace with |
| --- | --- |
| `https://redmine.example.com/logout` | `https://redmine.example.com/auth/saml/sls` |
| `https://redmine.example.com/auth/saml/slo` | `https://redmine.example.com/auth/saml/sls` |
| `https://redmine.example.com/auth/saml/spslo` | `https://redmine.example.com/auth/saml/sls` |

The setting is named differently per IdP product. Look for **Single Logout Service URL**, **Single Logout URL**, **SLO URL**, or **Logout Service URL**.

Redmine's own `/logout` keeps working as before for normal logout and for starting SP-initiated Single Logout. Only the handling of SAML messages sent by the IdP moved to `/auth/saml/sls`.

Incoming SLO messages are validated before any session is deleted, using the checks that apply to each message type:

- Both message types: the signature, a present Issuer, and a `Destination` matching this Redmine SLS endpoint. The Issuer is additionally compared with `idp_entity_id` when that optional setting is configured.
- `LogoutRequest`: also the NameID and, when the message carries one, the SessionIndex, matched against the SAML session being terminated.
- `LogoutResponse`: also `InResponseTo`, matched against the transaction of the LogoutRequest this Redmine sent.

That validation is implemented on the plugin's own `/auth/saml/sls` endpoint, so SLO handling is consolidated there instead of restoring the previous entry points.

Checklist for the upgrade:

1. Open the Redmine SAML client or application configuration in the IdP administration UI.
2. Locate the Single Logout Service / SLO / Logout URL setting.
3. If it is `/logout`, `/auth/saml/slo`, or `/auth/saml/spslo`, change it to `/auth/saml/sls`.
4. Keep the relative URL root prefix if Redmine uses one.
5. Leave the ACS URL `/auth/saml/callback` unchanged.
6. Sign in to Redmine through SAML and confirm that logout completes normally.

When the initializer sets `single_logout_service_url`, keep it aligned with the same URL, because that value is compared against the `Destination` of incoming SLO messages. A 1.0.6 initializer that omits the setting does not have to add it: the plugin then derives the expected `Destination` from `assertion_consumer_service_url`.

### Certificates, fingerprints, and SLO bindings

Use `idp_cert` for the normal configuration, or `idp_cert_multi` when multiple trusted IdP certificates are needed for certificate rollover. Full public certificates allow the plugin to verify both embedded XML signatures and HTTP-Redirect query signatures.

Fingerprint-only configuration remains supported for existing deployments and normal SAML login. Its SLO support depends on the binding:

- HTTP-POST SLO can be verified using the certificate embedded in the signed XML after its configured fingerprint is matched.
- HTTP-Redirect SLO requires a configured IdP public certificate to verify the query signature.
- Fingerprint-only HTTP-Redirect SLO is rejected rather than bypassing signature validation.

Do not configure `idp_cert`, `idp_cert_multi`, and `idp_cert_fingerprint` as simultaneous alternatives. The sample initializer uses `idp_cert` by default and shows the other approaches as commented alternatives.

### Sudo Mode re-authentication

Redmine's Sudo Mode asks for confirmation again before sensitive administrative actions once its timeout has passed. Redmine 7.0 enables Sudo Mode by default; on Redmine 6.0 and 6.1 it is only active when `sudo_mode: true` is set in `config/configuration.yml`.

The Redmine confirmation prompt asks for the local Redmine password, which SAML-only users do not have. Whenever Sudo Mode is enabled and the current Redmine session was created by SAML, this plugin therefore replaces that prompt with a SAML confirmation button. This works the same way on every supported Redmine version; it follows Redmine's own Sudo Mode setting, not the Redmine version. Pressing it sends a SAML `AuthnRequest` to the configured IdP and refreshes the Sudo Mode timestamp once the IdP confirms the same Redmine user.

That `AuthnRequest` is built from the SAML settings of your initializer, used unchanged. The plugin does not add or remove any authentication condition of its own, such as `ForceAuthn` or `IsPassive`. With a standard, static initializer that means the Sudo `AuthnRequest` carries the same authentication conditions as a normal SAML login: the same `ForceAuthn` and `IsPassive`, the same NameID policy and the same requested authentication context. If your deployment changes SAML settings per request through an OmniAuth `:setup` endpoint, see the known limitation below.

This behavior needs no configuration:

- No new initializer setting and no change to an existing initializer.
- No new IdP configuration, no additional ACS URL and no additional SAML provider. The existing `/auth/saml/callback` endpoint is reused.
- No database migration. The short-lived server-side record of a Sudo transaction uses Redmine's existing tokens table.

Optional wording of the confirmation prompt:

The three texts of the confirmation prompt can be changed in *Administration → Plugins → Redmine SAML*:

| Setting | Plugin setting key | Prompt element |
| --- | --- | --- |
| Sudo Mode confirmation heading | `saml_sudo_reauth_title` | the heading of the prompt |
| Sudo Mode confirmation text | `saml_sudo_reauth_text` | the explanation below the heading |
| Sudo Mode confirmation button label | `saml_sudo_reauth_button_label` | the label of the confirmation button |

All three are **optional** and blank by default:

- **Leave a setting blank and the prompt keeps the default wording of the current language.** Each text falls back on its own, so configuring one of them does not change the other two, and an installation that configures none of them shows exactly the prompt it showed before these settings existed, in every language. No default wording is copied into the settings.
- The values are **plain text**. HTML is not interpreted: it is escaped and shown as the characters that were entered.
- This applies to the SAML confirmation prompt only, in both its page and modal form. The local Redmine password prompt and the SAML login page are unaffected.

Keeping what you typed:

Redmine's own password prompt keeps the fields of the request it interrupted in hidden fields of that same page. A SAML confirmation leaves Redmine for the IdP, so that page is gone when you come back. To avoid losing a form you spent a long time on, the fields Redmine already selected for its own prompt are sealed into one opaque value that your browser keeps in the `sessionStorage` of that one tab while it visits the IdP. When you return, Redmine offers them back on a resume page and you press a button to submit them.

This needs no configuration and adds no setting, no migration and no server-side storage.

- **The confirmation never submits anything for you.** Coming back from the IdP only refreshes the Sudo Mode timestamp, exactly as before. The restored form is an ordinary Redmine form with a fresh CSRF token, and submitting it is a separate, explicit action of yours. A repeated or replayed SAML callback, or a reloaded page, therefore cannot cause the original change to happen.
- **The resumed request is checked like any other request.** It passes through Redmine's own Sudo Mode check again, so a successful SAML confirmation is never by itself the reason a change is allowed. If the confirmation lapsed again in the meantime, Redmine simply asks once more and the input is kept again.
- **The sealed value is unreadable and unforgeable outside your session.** It is encrypted and authenticated with `ActiveSupport::MessageEncryptor` using a key derived from your Redmine `secret_key_base`, and it is bound to the user and the login session that created it, with an expiry of 15 minutes. A modified, expired or foreign value is refused and nothing is restored.
- **The saved input is per tab and short lived.** Each continuation gets its own storage key, so two tabs never overwrite each other's input. The saved copy is removed when its restored form is explicitly submitted, and the browser drops any remaining copies when the tab closes.
- **SAML confirmation is single-flight per Redmine login session.** If one tab already has a live SAML Sudo transaction, pressing the confirmation button in another tab does not cancel or replace it and does not send a second `AuthnRequest`. The later tab restores and keeps its own input while asking you to finish the confirmation already in progress. A successful confirmation refreshes the Sudo timestamp for the whole Redmine login session, so you can then return to each tab and explicitly continue its own restored request. If the first confirmation fails or expires, continuing from a waiting tab asks for a new confirmation; it is not permanently blocked. Which request gets the transaction is decided by the unique index on Redmine's existing `tokens` table, so this holds for genuinely simultaneous tabs as well, on every database Redmine supports.
- **The scope is one login session, not one user.** A second browser, device or private window signs in as its own Redmine login session and gets its own SAML Sudo transaction, so confirming in one of them never cancels a confirmation in progress in another. The plugin uses the Redmine session token that Redmine already issues for every login session; it is only ever used as a domain-separated digest and never appears in a page, a URL, a log or a SAML message.

Limitations, in all of which the behaviour is simply the one from 1.2.0, with nothing changed and nothing restored:

- The input is kept for `POST`, `PUT`, `PATCH` and `DELETE` requests only. A `GET` has nothing worth keeping and its path is untouched.
- It needs JavaScript and a usable `sessionStorage`. Where either is unavailable the resume page says so and offers a link back, rather than failing.
- The Sudo modal shown for remote (XHR) forms is not resumed. The tab navigates away to the IdP, so the page that would have received the response no longer exists when it returns.
- A raw multipart file upload is not continued. Redmine's normal attachment flow uploads files before the form is submitted and sends only their tokens, which are kept like any other field; the raw-upload fallback used when JavaScript is off is refused rather than sealed into a browser store.

Details worth knowing:

- The transaction only refreshes the Sudo Mode timestamp. It never signs the user in again: the Redmine session, its session token, the autologin cookie and `last_login_on` are untouched, and the SAML `on_login` hook and on-the-fly user creation do not run. A SAML identity the confirmation response does not carry is kept as it was, so a confirmation never degrades the NameID or SessionIndex of the session.
- A Sudo transaction is recorded server side for five minutes. While that record is valid, the SAML Response answering it is still recognised as a Sudo confirmation after the transaction was used or cancelled, and also in a browser session that never started it, so it is not processed as a normal SAML login. The record then expires; it is a short-lived identification of Sudo transactions, not a change to how SAML Responses are handled in general. Nothing about normal SAML login changes: a login response, including an IdP-initiated one without an `InResponseTo`, is handled exactly as before.
- Starting a normal SAML login supersedes a pending Sudo confirmation of the same session, so the login completes normally.
- The re-authentication only succeeds when the IdP returns the same Redmine user. If a different account is used at the IdP, the confirmation fails and the current Redmine session is kept as it is; it is never replaced by the other account.
- The original request is not resubmitted automatically after returning from the IdP. When a continuation is available, Redmine restores it on a validated page and the user explicitly submits it from there; otherwise the action has to be repeated on the original page.
- A local Redmine login on a SAML-enabled Redmine keeps the standard Redmine password prompt.
- While Sudo Mode is disabled, this feature is not active in any form: Redmine never asks for confirmation, no SAML confirmation transaction can be started, and nothing about SAML login, logout or Single Logout changes.

Known limitation for request-scoped SAML configuration:

The Sudo `AuthnRequest` is built at `/saml/sudo_reauth` from the SAML settings of your initializer, not through the OmniAuth login request phase. Two optional, request-scoped mechanisms therefore do not reach it:

- an OmniAuth `:setup` endpoint that changes SAML settings per request, for example to select an IdP per tenant;
- `idp_sso_service_url_runtime_params`, which forwards request parameters of a login request to the IdP SSO URL.

Both keep working exactly as before for normal SAML login; this plugin does not replace or disable them. Only the Sudo confirmation uses the static settings instead. If your IdP needs one of those request-scoped values to route or identify the request, Sudo confirmation may not work in that deployment. A standard, static initializer needs no additional configuration for this.

IdP notes:

- Whether the IdP prompts the user again, asks only for a second factor, or answers straight from its existing SSO session is entirely an IdP policy decision, exactly as it is for a normal login. If you want the IdP to prompt again, configure that on the IdP side; the plugin does not request it.
- Whether the IdP issues a new SAML `SessionIndex` or NameID also depends on IdP policy. The plugin adopts the returned values only after it has confirmed that the same Redmine user answered, and it reissues its Single Logout context accordingly.

### Production logging

For troubleshooting compatibility, INFO logs may include the SAML Response and mapped attributes. SP private keys and other secrets are redacted, but SAML Responses and attributes may contain personal information. Restrict access to production logs and manage their retention period appropriately.

## Uninstall

```shell
export REDMINE_ROOT=/path/to/redmine
cd "$REDMINE_ROOT"

bundle exec rake redmine:plugins:migrate NAME=redmine_saml VERSION=0 RAILS_ENV=production
rm -rf plugins/redmine_saml public/plugin_assets/redmine_saml
```

Restart the Redmine application server after uninstalling the plugin.

## Support and contribution

The currently maintained repository is [nrswnrsw/redmine_saml](https://github.com/nrswnrsw/redmine_saml). This is a maintainer-managed project; public Issue and Pull Request contributions are not accepted. The source remains available for viewing, cloning, and forking.

## Credits

This repository continues the Redmine SAML plugin originally maintained by [AlphaNodes GmbH](https://alphanodes.com/) at [alphanodes/redmine_saml](https://github.com/alphanodes/redmine_saml).

The original project credits these earlier implementations:

- <https://github.com/chrodriguez/redmine_omniauth_saml>
- <https://github.com/jbbarth/redmine_omniauth_cas>

Many thanks to the original authors and contributors.
