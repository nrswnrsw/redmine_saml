# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SudoContextTest < RedmineSaml::TestCase
  fixtures :users

  setup do
    RedmineSaml::SudoTokenStore.register_action!
    @user = users :users_001
    @settings = RedmineSaml.configured_saml
    @nonce = RedmineSaml::SudoReauth.generate_nonce
    @token = RedmineSaml::SudoTokenStore.create_transaction @user
  end

  test 'builds a context that keeps only the AuthnRequest ID in clear text' do
    context = build_context

    assert_equal RedmineSaml::SudoContext::VERSION, context['version']
    assert_equal RedmineSaml::SudoContext::TYPE, context['type']
    assert_equal @user.id, context['user_id']
    assert_equal '_authn-request-id', context['request_id']
    assert_equal @token.id, context['token_id']
    assert_not_includes context.values, @nonce
    assert_not_includes context.values, @token.value
    assert_match RedmineSaml::SudoContext::DIGEST_PATTERN, context['nonce_verifier']
    assert_match RedmineSaml::SudoContext::DIGEST_PATTERN, context['token_verifier']
  end

  test 'keeps the SAML session snapshot needed to roll a failed transaction back' do
    context = build_context saml_uid: 'previous-name-id',
                            saml_session_index: '_previous-session-index'

    assert_equal 'previous-name-id', context['saml_uid']
    assert_equal '_previous-session-index', context['saml_session_index']

    empty_context = build_context saml_uid: nil, saml_session_index: nil

    assert_nil empty_context['saml_uid']
    assert_nil empty_context['saml_session_index']
  end

  test 'loads a well formed context' do
    context = build_context

    assert_equal context, load_context(context)
  end

  test 'rejects a context with a foreign version or type' do
    assert_nil load_context(build_context.merge('version' => 99))
    assert_nil load_context(build_context.merge('type' => 'slo'))
  end

  test 'rejects a context with tampered identifiers' do
    assert_nil load_context(build_context.merge('user_id' => 0))
    assert_nil load_context(build_context.merge('user_id' => '1'))
    assert_nil load_context(build_context.merge('token_id' => nil))
    assert_nil load_context(build_context.merge('token_created_at' => 'now'))
    assert_nil load_context(build_context.merge('request_id' => ''))
    assert_nil load_context(build_context.merge('nonce_verifier' => 'not-a-digest'))
    assert_nil load_context(build_context.merge('token_verifier' => 'not-a-digest'))
  end

  test 'rejects a context issued for a different SAML configuration' do
    other_settings = @settings.merge idp_sso_service_url: 'https://other.idp.example/sso'
    context = RedmineSaml::SudoContext.build(
      user_id: @user.id,
      request_id: '_authn-request-id',
      nonce: @nonce,
      token: @token,
      return_url: '/projects',
      saml_uid: nil,
      saml_session_index: nil,
      settings: other_settings
    )

    assert_nil load_context(context)
  end

  test 'rejects an expired or future dated context' do
    now = Time.current
    expired = build_context now: now - RedmineSaml::SudoContext::VALIDITY - 1.second
    future = build_context now: now + RedmineSaml::SudoContext::CLOCK_SKEW + 10.seconds

    assert_nil load_context(expired, now: now)
    assert_nil load_context(future, now: now)
    assert load_context(build_context(now: now - RedmineSaml::SudoContext::VALIDITY + 5.seconds), now: now)
  end

  test 'rejects anything that is not a context hash' do
    assert_nil load_context(nil)
    assert_nil load_context('')
    assert_nil load_context({})
  end

  test 'matches the RelayState nonce in constant time and rejects a wrong one' do
    context = build_context

    assert RedmineSaml::SudoContext.matching_nonce?(context, @nonce)
    assert_not RedmineSaml::SudoContext.matching_nonce?(context, RedmineSaml::SudoReauth.generate_nonce)
    assert_not RedmineSaml::SudoContext.matching_nonce?(context, '')
    assert_not RedmineSaml::SudoContext.matching_nonce?(context, nil)
    assert_not RedmineSaml::SudoContext.matching_nonce?(nil, @nonce)
  end

  test 'matches the AuthnRequest ID and fails closed without one' do
    context = build_context

    assert RedmineSaml::SudoContext.matching_request_id?(context, '_authn-request-id')
    assert_not RedmineSaml::SudoContext.matching_request_id?(context, '_other-request-id')
    assert_not RedmineSaml::SudoContext.matching_request_id?(context, nil)
    assert_not RedmineSaml::SudoContext.matching_request_id?(context, '')
    assert_not RedmineSaml::SudoContext.matching_request_id?(nil, '_authn-request-id')
    assert_not RedmineSaml::SudoContext.matching_request_id?(context.merge('request_id' => ''), '')
  end

  private

  def build_context(saml_uid: 'previous-name-id', saml_session_index: '_previous-session-index', now: Time.current)
    RedmineSaml::SudoContext.build(
      user_id: @user.id,
      request_id: '_authn-request-id',
      nonce: @nonce,
      token: @token,
      return_url: '/projects',
      saml_uid: saml_uid,
      saml_session_index: saml_session_index,
      settings: @settings,
      now: now
    )
  end

  def load_context(context, now: Time.current)
    RedmineSaml::SudoContext.load_context context, settings: @settings, now: now
  end
end
