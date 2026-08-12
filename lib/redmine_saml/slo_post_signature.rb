# frozen_string_literal: true

module RedmineSaml
  # Validates the XML signature of an HTTP-POST binding SAML logout message.
  #
  # ruby-saml does not verify the message signature of SloLogoutrequest and
  # Logoutresponse for the HTTP-POST binding, so this plugin verifies it here.
  # The checks below reject signature wrapping by requiring exactly one signature
  # on the document root and exactly one element carrying the signed ID.
  class SloPostSignature
    class << self
      def valid?(document, settings:)
        signed_document = XMLSecurity::SignedDocument.new document.to_s
        root_id = signed_document.root&.attributes&.[]('ID').to_s
        signed_element_id = signed_document.signed_element_id.to_s
        return false if root_id.blank? || root_id != signed_element_id

        namespaces = { 'ds' => XMLSecurity::BaseDocument::DSIG }
        signatures = REXML::XPath.match signed_document, '//ds:Signature', namespaces
        root_signatures = REXML::XPath.match signed_document.root, './ds:Signature', namespaces
        elements_with_signed_id = REXML::XPath.match(
          signed_document,
          '//*[@ID=$id]',
          {},
          { 'id' => signed_element_id }
        )
        return false unless signatures.one? && root_signatures.one? && elements_with_signed_id.one?

        valid_post_saml_certificate_signature? signed_document, settings: settings
      end

      private

      def valid_post_saml_certificate_signature?(signed_document, settings:)
        idp_certs = settings.get_idp_cert_multi
        signing_certs = idp_certs && idp_certs[:signing]

        if signing_certs.present?
          signing_certs.any? do |certificate|
            signed_document.validate_document_with_cert(certificate, true) && valid_idp_certificate?(certificate, settings: settings)
          end
        else
          certificate = settings.get_idp_cert
          if certificate.present?
            return signed_document.validate_document_with_cert(certificate, true) &&
                   valid_idp_certificate?(certificate, settings: settings)
          end

          fingerprint = settings.get_fingerprint
          return false if fingerprint.blank?

          certificate = saml_signature_certificate signed_document
          return false if certificate.blank?

          options = { fingerprint_alg: settings.idp_cert_fingerprint_algorithm }
          signed_document.validate_document(fingerprint, true, options) &&
            valid_idp_certificate?(certificate, settings: settings)
        end
      end

      def saml_signature_certificate(signed_document)
        namespaces = { 'ds' => XMLSecurity::BaseDocument::DSIG }
        certificates = REXML::XPath.match signed_document, '//ds:X509Certificate', namespaces
        signature_certificates = REXML::XPath.match(
          signed_document.root,
          './ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
          namespaces
        )
        return unless certificates.one? && signature_certificates.one? && certificates.first.equal?(signature_certificates.first)

        certificate_data = OneLogin::RubySaml::Utils.element_text signature_certificates.first
        return if certificate_data.blank?

        OpenSSL::X509::Certificate.new Base64.decode64(certificate_data)
      rescue ArgumentError, OpenSSL::X509::CertificateError
        nil
      end

      def valid_idp_certificate?(certificate, settings:)
        return true unless settings.security[:check_idp_cert_expiration]

        certificate.present? && !OneLogin::RubySaml::Utils.is_cert_expired(certificate)
      end
    end
  end
end
