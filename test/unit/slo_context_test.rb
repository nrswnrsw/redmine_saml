# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SloContextTest < RedmineSaml::TestCase
  TokenValue = Struct.new :id, :value, :created_on

  setup do
    @settings = RedmineSaml.configured_saml.deep_dup
    @now = Time.current
    @token = TokenValue.new 123, 'VERY_SECRET_TOKEN_VALUE', @now
  end

  test 'active context contains only digests for session credentials and SAML identifiers' do
    context = RedmineSaml::SloContext.active(
      user_id: 5,
      token: @token,
      name_id: 'user-name-id',
      session_index: 'session-index',
      settings: @settings,
      now: @now
    )
    serialized = RedmineSaml::SloContext.dump context

    assert_not_includes serialized, @token.value
    assert_not_includes serialized, 'user-name-id'
    assert_not_includes serialized, 'session-index'
    assert RedmineSaml::SloContext.matching_name_id?(context, 'user-name-id')
    assert RedmineSaml::SloContext.matching_session_indexes?(context, ['session-index'])
    assert_not RedmineSaml::SloContext.matching_session_indexes?(context, ['another-session'])
    assert_equal context,
                 RedmineSaml::SloContext.load_active(serialized, settings: @settings, now: @now)
  end

  test 'active context keeps the legacy optional SessionIndex semantics' do
    context = RedmineSaml::SloContext.active(
      user_id: 5,
      token: @token,
      name_id: 'user-name-id',
      session_index: nil,
      settings: @settings,
      now: @now
    )

    assert RedmineSaml::SloContext.matching_session_indexes?(context, [])
    assert_not RedmineSaml::SloContext.matching_session_indexes?(context, ['unexpected-session'])
  end

  test 'context rejects an unknown version and a changed SAML configuration' do
    context = RedmineSaml::SloContext.active(
      user_id: 5,
      token: @token,
      name_id: 'user-name-id',
      session_index: nil,
      settings: @settings,
      now: @now
    )

    unknown_version = context.merge 'version' => 2
    assert_nil RedmineSaml::SloContext.load_active(unknown_version, settings: @settings, now: @now)

    changed_settings = @settings.merge idp_slo_service_url: 'https://another-idp.example.test/slo'
    assert_nil RedmineSaml::SloContext.load_active(context, settings: changed_settings, now: @now)
  end

  test 'pending context expires after five minutes and does not contain the Token value' do
    context = RedmineSaml::SloContext.pending(
      transaction_id: '_saml-request-id',
      user_id: 5,
      token: @token,
      login: 'jsmith',
      settings: @settings,
      now: @now
    )
    serialized = RedmineSaml::SloContext.dump context

    assert_not_includes serialized, @token.value
    assert RedmineSaml::SloContext.load_pending(serialized, settings: @settings, now: @now + 5.minutes)
    assert_nil RedmineSaml::SloContext.load_pending(serialized, settings: @settings, now: @now + 5.minutes + 1.second)
  end

  test 'config digest keys and their meaning are unchanged' do
    assert_equal %i[sp_entity_id idp_entity_id single_logout_service_url idp_slo_service_url idp_slo_response_service_url],
                 RedmineSaml::SloContext::CONFIG_KEYS

    changed_settings = @settings.merge single_logout_service_url: 'https://changed.example.test/auth/saml/sls'

    assert_not_equal RedmineSaml::SloContext.config_digest(@settings),
                     RedmineSaml::SloContext.config_digest(changed_settings)
  end
end
