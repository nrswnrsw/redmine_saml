# frozen_string_literal: true

require Rails.root.join('plugins/redmine_saml/lib/redmine_saml')
require Rails.root.join('plugins/redmine_saml/lib/redmine_saml/base')

RedmineSaml::Base.configure do |config|
  config.saml = {
    # Redmine callback URL
    assertion_consumer_service_url: "https://redmine.example.com#{RedmineSaml::CALLBACK_PATH}",
    # The SP issuer / entity ID. Must be a URI as defined by SAML 2.0.
    sp_entity_id: "https://redmine.example.com#{RedmineSaml::METADATA_PATH}",
    # Public Redmine SLS URL. It must exactly match the SAML Destination.
    single_logout_service_url: "https://redmine.example.com#{RedmineSaml::LOGOUT_SERVICE_PATH}",
    # IdP SSO login endpoint
    idp_sso_service_url: 'https://idp.example.com/saml/sso',
    # Optional but recommended. When set, SAML logout message issuers must match it.
    idp_entity_id: 'https://idp.example.com/saml/metadata',
    # IdP signing certificate. A full certificate also supports Redirect Binding SLO validation.
    idp_cert: '-----BEGIN CERTIFICATE-----
IDP_CERTIFICATE_CONTENT
-----END CERTIFICATE-----',
    # Alternatively, use both SHA-256 fingerprint settings below instead of idp_cert.
    # Fingerprint-only configurations cannot validate Redirect Binding SLO.
    # idp_cert_fingerprint: 'SHA-256_CERTIFICATE_FINGERPRINT',
    # idp_cert_fingerprint_algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    # For IdP certificate rollover, replace idp_cert with idp_cert_multi, for example:
    # idp_cert_multi: {
    #   signing: ['OLD_IDP_SIGNING_CERTIFICATE', 'NEW_IDP_SIGNING_CERTIFICATE'],
    #   encryption: ['IDP_ENCRYPTION_CERTIFICATE']
    # },
    name_identifier_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    # Legacy IdP sign-out URL used for failed-login cleanup and to enable SP-initiated SLO.
    # The SAML LogoutRequest itself is sent to idp_slo_service_url.
    signout_url: 'https://idp.example.com/logout?return_to=',
    # IdP Single Logout Service endpoint
    idp_slo_service_url: 'https://idp.example.com/saml/slo',
    # Optional response endpoint for IdP-initiated SLO; falls back to idp_slo_service_url.
    # idp_slo_response_service_url: 'https://idp.example.com/saml/slo/response',
    # Redmine field used as the NameID for SAML logout
    name_identifier_value: 'mail',
    # Override the attribute mapping separator, if required
    # attribute_mapping_sep: '|',
    attribute_mapping: {
      # How will we map attributes from SSO to redmine attributes
      # using either urn:oid:identifier, or friendly names, e.g.
      # mail: 'extra|raw_info|urn:oid:0.9.2342.19200300.100.1.3'
      # or
      # mail: 'extra|raw_info|email'
      #
      # These four mappings are required. Edit the paths to match your IdP attributes.
      login: 'extra|raw_info|username',
      mail: 'extra|raw_info|email',
      firstname: 'extra|raw_info|firstname',
      lastname: 'extra|raw_info|lastname'
    }
  }

  # Legacy configurations may contain an admin mapping, but the current plugin does not apply it.

  config.on_login do |omniauth_hash, user|
    # Implement any hook you want here
  end
end
