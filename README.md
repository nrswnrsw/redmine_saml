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

Existing AlphaNodes users can normally keep their current initializer unchanged. No new SAML setting is required solely to move to this maintained repository.

1. Preserve the existing file under `config/initializers/` and any deployment-specific configuration.
2. Replace the code in `plugins/redmine_saml` with the current `nrswnrsw/redmine_saml` version.
3. Keep the directory name exactly `redmine_saml`.
4. Run `bundle install` from the Redmine root.
5. Run `bundle exec rake redmine:plugins:migrate RAILS_ENV=production`.
6. Restart the Redmine application server.

Additionals is no longer required by this plugin. It does not need to be removed from an existing Redmine installation.

Optional settings such as `idp_entity_id` can strengthen validation, but they are not migration requirements for existing initializers.

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

### Certificates, fingerprints, and SLO bindings

Use `idp_cert` for the normal configuration, or `idp_cert_multi` when multiple trusted IdP certificates are needed for certificate rollover. Full public certificates allow the plugin to verify both embedded XML signatures and HTTP-Redirect query signatures.

Fingerprint-only configuration remains supported for existing deployments and normal SAML login. Its SLO support depends on the binding:

- HTTP-POST SLO can be verified using the certificate embedded in the signed XML after its configured fingerprint is matched.
- HTTP-Redirect SLO requires a configured IdP public certificate to verify the query signature.
- Fingerprint-only HTTP-Redirect SLO is rejected rather than bypassing signature validation.

Do not configure `idp_cert`, `idp_cert_multi`, and `idp_cert_fingerprint` as simultaneous alternatives. The sample initializer uses `idp_cert` by default and shows the other approaches as commented alternatives.

## Uninstall

```shell
export REDMINE_ROOT=/path/to/redmine
cd "$REDMINE_ROOT"

bundle exec rake redmine:plugins:migrate NAME=redmine_saml VERSION=0 RAILS_ENV=production
rm -rf plugins/redmine_saml public/plugin_assets/redmine_saml
```

Restart the Redmine application server after uninstalling the plugin.

## Support and contribution

The currently maintained repository is [nrswnrsw/redmine_saml](https://github.com/nrswnrsw/redmine_saml). Please use its [issue tracker](https://github.com/nrswnrsw/redmine_saml/issues) for bug reports and feature requests. Pull requests are welcome.

## Credits

This repository continues the Redmine SAML plugin originally maintained by [AlphaNodes GmbH](https://alphanodes.com/) at [alphanodes/redmine_saml](https://github.com/alphanodes/redmine_saml).

The original project credits these earlier implementations:

- <https://github.com/chrodriguez/redmine_omniauth_saml>
- <https://github.com/jbbarth/redmine_omniauth_cas>

Many thanks to the original authors and contributors.
