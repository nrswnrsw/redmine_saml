# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class AuthHashLoggingTest < RedmineSaml::TestCase
  SP_PRIVATE_KEY = 'VERY_SECRET_UNIT_TEST_PRIVATE_KEY'
  RESPONSE_XML = '<samlp:Response ID="_unit-test-response">RESPONSE_XML_FIXTURE</samlp:Response>'
  DECRYPTED_XML = '<saml:Assertion>DECRYPTED_ASSERTION_FIXTURE</saml:Assertion>'

  SettingsDouble = Struct.new :private_key
  ResponseDouble = Struct.new :response, :decrypted_document, :settings
  ResponseWithoutDecryptedDocument = Struct.new :response

  # Stands in for an object that is not safe to inspect into a log.
  class SecretBearer
    INSPECT_PAYLOAD = 'VERY_SECRET_UNIT_TEST_INSPECT_PAYLOAD'

    def inspect
      "#<SecretBearer #{INSPECT_PAYLOAD}>"
    end
  end

  test 'keeps the SAML identifiers and info of an OmniAuth AuthHash' do
    result = auth_hash_for_logging saml_auth_hash

    assert_includes result, 'saml'
    assert_includes result, '_unit-test-name-id'
    assert_includes result, '_unit-test-session-index'
    assert_includes result, 'unit-test@example.test'
  end

  test 'reads symbol keys from a plain Hash' do
    result = auth_hash_for_logging(provider: 'saml',
                                   uid: '_symbol-key-uid',
                                   extra: { session_index: '_symbol-key-session-index' })

    assert_includes result, '_symbol-key-uid'
    assert_includes result, '_symbol-key-session-index'
  end

  test 'falls back to string keys when the Hash has no symbol key' do
    result = auth_hash_for_logging('provider' => 'saml',
                                   'uid' => '_string-key-uid',
                                   'extra' => { 'session_index' => '_string-key-session-index' })

    assert_includes result, '_string-key-uid'
    assert_includes result, '_string-key-session-index'
  end

  test 'expands SAML attributes that respond to all' do
    raw_info = OneLogin::RubySaml::Attributes.new 'department-unit-test' => ['Engineering']
    result = auth_hash_for_logging saml_auth_hash(raw_info: raw_info)

    assert_includes result, 'department-unit-test'
    assert_includes result, 'Engineering'
  end

  test 'expands SAML attributes given as a plain Hash' do
    result = auth_hash_for_logging saml_auth_hash(raw_info: { 'plain-attribute' => ['plain-value'] })

    assert_includes result, 'plain-attribute'
    assert_includes result, 'plain-value'
  end

  test 'keeps the SAML Response XML and the decrypted document' do
    result = auth_hash_for_logging saml_auth_hash

    assert_includes result, "response=#{RESPONSE_XML.inspect}"
    assert_includes result, "decrypted_document=#{DECRYPTED_XML.inspect}"
  end

  test 'never logs the SP private key held by the ruby-saml Settings' do
    result = auth_hash_for_logging saml_auth_hash

    assert_not_includes result, SP_PRIVATE_KEY
    assert_not_includes result, 'SettingsDouble'
  end

  test 'logs a nil decrypted document when the response does not provide one' do
    response_object = ResponseWithoutDecryptedDocument.new RESPONSE_XML
    result = auth_hash_for_logging saml_auth_hash(response_object: response_object)

    assert_includes result, "response=#{RESPONSE_XML.inspect}"
    assert_includes result, 'decrypted_document=nil'
  end

  test 'logs a nil response object when it does not look like a SAML Response' do
    result = auth_hash_for_logging saml_auth_hash(response_object: SecretBearer.new)

    assert_includes result, 'response_object=nil'
    assert_not_includes result, SecretBearer::INSPECT_PAYLOAD
  end

  test 'replaces an object outside the log allowlist with its class name' do
    result = auth_hash_for_logging saml_auth_hash(info: { 'payload' => SecretBearer.new })

    assert_includes result, '[AuthHashLoggingTest::SecretBearer]'
    assert_not_includes result, SecretBearer::INSPECT_PAYLOAD
  end

  test 'replaces objects nested in Hashes and Arrays with their class name' do
    info = {
      'nested' => { 'inner' => SecretBearer.new },
      'listed' => [SecretBearer.new, 'plain-string']
    }
    result = auth_hash_for_logging saml_auth_hash(info: info)

    assert_equal 2, result.scan('[AuthHashLoggingTest::SecretBearer]').size
    assert_includes result, 'plain-string'
    assert_not_includes result, SecretBearer::INSPECT_PAYLOAD
  end

  test 'does not modify the AuthHash or the objects it carries' do
    settings = SettingsDouble.new SP_PRIVATE_KEY
    response_object = ResponseDouble.new RESPONSE_XML, DECRYPTED_XML, settings
    auth = saml_auth_hash response_object: response_object

    auth_hash_for_logging auth

    assert_same response_object, auth[:extra][:response_object]
    assert_same settings, response_object.settings
    assert_equal SP_PRIVATE_KEY, response_object.settings.private_key
    assert_equal RESPONSE_XML, response_object.response
    assert_equal DECRYPTED_XML, response_object.decrypted_document
    assert_includes auth.inspect, SP_PRIVATE_KEY
  end

  private

  def auth_hash_for_logging(omniauth)
    RedmineSaml::AuthHashLogging.auth_hash_for_logging omniauth
  end

  def saml_auth_hash(info: nil, raw_info: nil, response_object: nil)
    OmniAuth::AuthHash.new(
      provider: 'saml',
      uid: '_unit-test-name-id',
      info: info || { 'email' => 'unit-test@example.test' },
      extra: {
        raw_info: raw_info || { 'email' => ['unit-test@example.test'] },
        session_index: '_unit-test-session-index',
        response_object: response_object || default_response_object
      }
    )
  end

  def default_response_object
    ResponseDouble.new RESPONSE_XML, DECRYPTED_XML, SettingsDouble.new(SP_PRIVATE_KEY)
  end
end
