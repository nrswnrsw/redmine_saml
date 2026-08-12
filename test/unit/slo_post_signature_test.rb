# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'base64'
require 'openssl'
require 'rexml/document'

class SloPostSignatureTest < RedmineSaml::TestCase
  IDP_SLO_SERVICE_URL = 'https://idp.example.test/saml/slo'
  IDP_ENTITY_ID = 'https://idp.example.test/metadata'
  NAME_ID = 'user@example.test'
  NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'

  class << self
    def signing_private_key
      @signing_private_key ||= OpenSSL::PKey::RSA.new 2048
    end

    def other_private_key
      @other_private_key ||= OpenSSL::PKey::RSA.new 2048
    end

    def signing_certificate
      @signing_certificate ||= build_certificate serial: 1,
                                                 common_name: 'redmine-saml-post-signature-test-idp',
                                                 not_before: Time.now.utc - 3600,
                                                 not_after: Time.now.utc + 86_400
    end

    def expired_signing_certificate
      @expired_signing_certificate ||= build_certificate serial: 2,
                                                         common_name: 'expired-redmine-saml-post-signature-test-idp',
                                                         not_before: Time.now.utc - 7200,
                                                         not_after: Time.now.utc - 3600
    end

    def other_certificate
      @other_certificate ||= build_certificate serial: 3,
                                               common_name: 'other-redmine-saml-post-signature-test-idp',
                                               not_before: Time.now.utc - 3600,
                                               not_after: Time.now.utc + 86_400,
                                               private_key: other_private_key
    end

    private

    def build_certificate(serial:, common_name:, not_before:, not_after:, private_key: signing_private_key)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = serial
      name = OpenSSL::X509::Name.parse "/CN=#{common_name}"
      certificate.subject = name
      certificate.issuer = name
      certificate.public_key = private_key.public_key
      certificate.not_before = not_before
      certificate.not_after = not_after
      digest = OpenSSL::Digest.new 'SHA256'
      certificate.sign private_key, digest
      certificate
    end
  end

  test 'accepts a signed POST LogoutRequest for the configured IdP certificate' do
    valid = RedmineSaml::SloPostSignature.valid? signed_logout_request_xml,
                                                 settings: certificate_settings

    assert valid
  end

  test 'rejects an unsigned POST LogoutRequest' do
    valid = RedmineSaml::SloPostSignature.valid? signed_logout_request_xml(signed: false),
                                                 settings: certificate_settings

    assert_not valid
  end

  test 'rejects a POST LogoutRequest whose root ID does not match the signed element ID' do
    xml = tamper_root_id signed_logout_request_xml

    valid = RedmineSaml::SloPostSignature.valid? xml, settings: certificate_settings

    assert_not valid
  end

  test 'rejects a POST LogoutRequest carrying the signed ID on more than one element' do
    xml = duplicate_signed_id signed_logout_request_xml

    valid = RedmineSaml::SloPostSignature.valid? xml, settings: certificate_settings

    assert_not valid
  end

  test 'rejects a POST LogoutRequest with a wrapped second signature' do
    xml = wrap_second_signature signed_logout_request_xml

    valid = RedmineSaml::SloPostSignature.valid? xml, settings: certificate_settings

    assert_not valid
  end

  test 'rejects a POST LogoutRequest signed with a key other than the configured IdP certificate' do
    xml = signed_logout_request_xml certificate: self.class.other_certificate,
                                    private_key: self.class.other_private_key

    valid = RedmineSaml::SloPostSignature.valid? xml, settings: certificate_settings

    assert_not valid
  end

  test 'accepts a fingerprint-only POST LogoutRequest with a matching unexpired certificate' do
    valid = RedmineSaml::SloPostSignature.valid? signed_logout_request_xml,
                                                 settings: fingerprint_settings

    assert valid
  end

  test 'rejects a fingerprint-only POST LogoutRequest when the fingerprint does not match' do
    settings = fingerprint_settings certificate: self.class.other_certificate

    valid = RedmineSaml::SloPostSignature.valid? signed_logout_request_xml, settings: settings

    assert_not valid
  end

  test 'rejects a fingerprint-only POST LogoutRequest with an expired certificate' do
    certificate = self.class.expired_signing_certificate
    xml = signed_logout_request_xml certificate: certificate

    valid = RedmineSaml::SloPostSignature.valid? xml, settings: fingerprint_settings(certificate: certificate)

    assert_not valid
  end

  private

  # Builds a signed HTTP-POST binding LogoutRequest the way an IdP would send it.
  def signed_logout_request_xml(certificate: self.class.signing_certificate,
                                private_key: self.class.signing_private_key,
                                signed: true)
    settings = OneLogin::RubySaml::Settings.new
    settings.idp_slo_service_url = IDP_SLO_SERVICE_URL
    settings.idp_slo_service_binding = :post
    settings.sp_entity_id = IDP_ENTITY_ID
    settings.name_identifier_value = NAME_ID
    settings.name_identifier_format = NAME_ID_FORMAT
    settings.compress_request = false
    if signed
      settings.certificate = certificate.to_pem
      settings.private_key = private_key.to_pem
    end
    settings.security[:logout_requests_signed] = signed
    settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
    settings.security[:digest_method] = XMLSecurity::Document::SHA256

    request_params = OneLogin::RubySaml::Logoutrequest.new.create_params settings

    Base64.decode64 request_params['SAMLRequest']
  end

  def certificate_settings(certificate: self.class.signing_certificate)
    OneLogin::RubySaml::Settings.new idp_cert: certificate.to_pem
  end

  def fingerprint_settings(certificate: self.class.signing_certificate)
    OneLogin::RubySaml::Settings.new.tap do |settings|
      settings.idp_cert_fingerprint = sha1_fingerprint certificate
      settings.security[:check_idp_cert_expiration] = true
    end
  end

  def sha1_fingerprint(certificate)
    OpenSSL::Digest::SHA1.hexdigest(certificate.to_der).scan(/../).join ':'
  end

  def tamper_root_id(xml)
    document = REXML::Document.new xml
    document.root.attributes['ID'] = '_tampered-root-id'
    document.to_s
  end

  def duplicate_signed_id(xml)
    document = REXML::Document.new xml
    duplicate = document.root.add_element 'Duplicate'
    duplicate.add_attribute 'ID', document.root.attributes['ID']
    document.to_s
  end

  def wrap_second_signature(xml)
    document = REXML::Document.new xml
    signature = REXML::XPath.first document, '//ds:Signature', 'ds' => XMLSecurity::BaseDocument::DSIG

    assert signature, 'Expected the fixture LogoutRequest to carry an XML signature'

    wrapper = document.root.add_element 'Wrapper'
    wrapper.add_element signature.deep_clone
    document.to_s
  end
end
