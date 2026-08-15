# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'xml_security'

module RedmineSaml
  # Builds SAML Responses for tests.
  #
  # OmniAuth test mode replaces the whole callback phase, so it can never show
  # what ruby-saml does with a Response. Tests that have to prove something
  # about the real callback phase build a Response here instead, optionally
  # signed by a throwaway IdP key, and post it through the middleware exactly
  # as an IdP would.
  module SamlResponseBuilder
    ACS_URL = "http://localhost#{RedmineSaml::CALLBACK_PATH}".freeze
    SP_ENTITY_ID = "http://localhost#{RedmineSaml::METADATA_PATH}".freeze
    IDP_ENTITY_ID = 'https://idp.example.test/metadata'
    NAME_ID = 'name-id@example.test'
    SESSION_INDEX = '_saml-session-index'
    LOGIN = 'admin'
    MAIL = 'admin@somenet.foo'

    # The attribute mapping a Response built here satisfies. Real SAML
    # attributes, unlike the flat mock mapping of the OmniAuth test mode.
    ATTRIBUTE_MAPPING = {
      login: 'extra|raw_info|username',
      mail: 'extra|raw_info|emailaddress',
      firstname: 'extra|raw_info|givenname',
      lastname: 'extra|raw_info|surname'
    }.freeze

    class << self
      # A self signed throwaway IdP certificate. Generated once per process,
      # because an RSA key pair is expensive and none of this is a secret.
      def credentials
        @credentials ||= begin
          key = OpenSSL::PKey::RSA.new 2048
          [key, self_signed_certificate(key)]
        end
      end

      def key
        credentials.first
      end

      def certificate
        credentials.last
      end

      # SAML settings that accept what this builder produces.
      def settings_overrides
        { idp_cert: certificate.to_pem,
          attribute_mapping: ATTRIBUTE_MAPPING.dup }
      end

      def encoded(signed: true, **options)
        xml = document(**options)
        xml = sign(xml) if signed
        Base64.encode64 xml
      end

      def document(in_response_to: nil, name_id: NAME_ID, session_index: SESSION_INDEX,
                   login: LOGIN, mail: MAIL, now: Time.now.utc)
        <<~XML
          <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                          ID="_#{SecureRandom.uuid}" Version="2.0" IssueInstant="#{stamp now}"
                          Destination="#{ACS_URL}"#{in_response_to_attribute in_response_to}>
            <saml:Issuer>#{IDP_ENTITY_ID}</saml:Issuer>
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            <saml:Assertion ID="_#{SecureRandom.uuid}" Version="2.0" IssueInstant="#{stamp now}">
              <saml:Issuer>#{IDP_ENTITY_ID}</saml:Issuer>
              <saml:Subject>
                #{name_id_element name_id}
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                  <saml:SubjectConfirmationData NotOnOrAfter="#{stamp now + 300}"
                                                Recipient="#{ACS_URL}"#{in_response_to_attribute in_response_to}/>
                </saml:SubjectConfirmation>
              </saml:Subject>
              <saml:Conditions NotBefore="#{stamp now - 60}" NotOnOrAfter="#{stamp now + 300}">
                <saml:AudienceRestriction><saml:Audience>#{SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction>
              </saml:Conditions>
              <saml:AuthnStatement AuthnInstant="#{stamp now}"#{session_index_attribute session_index}
                                   SessionNotOnOrAfter="#{stamp now + 300}">
                <saml:AuthnContext>
                  <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                </saml:AuthnContext>
              </saml:AuthnStatement>
              <saml:AttributeStatement>
                <saml:Attribute Name="username"><saml:AttributeValue>#{login}</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="emailaddress"><saml:AttributeValue>#{mail}</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="givenname"><saml:AttributeValue>Redmine</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="surname"><saml:AttributeValue>Admin</saml:AttributeValue></saml:Attribute>
              </saml:AttributeStatement>
            </saml:Assertion>
          </samlp:Response>
        XML
      end

      private

      def sign(xml)
        document = XMLSecurity::Document.new xml
        document.sign_document key,
                               certificate,
                               XMLSecurity::Document::RSA_SHA256,
                               XMLSecurity::Document::SHA256
        document.to_s
      end

      def self_signed_certificate(key)
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = 1
        certificate.subject = OpenSSL::X509::Name.parse '/CN=redmine-saml-test-idp'
        certificate.issuer = certificate.subject
        certificate.public_key = key.public_key
        # Generated once per process and possibly under a travelled clock, so
        # the validity has to cover real time either way.
        certificate.not_before = Time.now.utc - 10.years
        certificate.not_after = Time.now.utc + 10.years
        certificate.sign key, OpenSSL::Digest.new('SHA256')
        certificate
      end

      def stamp(time)
        time.strftime '%Y-%m-%dT%H:%M:%SZ'
      end

      def in_response_to_attribute(in_response_to)
        return '' if in_response_to.blank?

        %( InResponseTo="#{in_response_to}")
      end

      def session_index_attribute(session_index)
        return '' if session_index.blank?

        %( SessionIndex="#{session_index}")
      end

      def name_id_element(name_id)
        return '' if name_id.blank?

        %(<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">#{name_id}</saml:NameID>)
      end
    end
  end
end
