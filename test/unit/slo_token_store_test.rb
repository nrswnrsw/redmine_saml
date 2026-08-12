# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SloTokenStoreTest < RedmineSaml::TestCase
  fixtures :users

  setup do
    RedmineSaml::SloTokenStore.register_action!
    @user = users :users_001
    @settings = RedmineSaml.configured_saml
  end

  test 'registers a short lived plugin action without colliding with Redmine actions' do
    RedmineSaml::SloTokenStore.register_action!
    options = Token.actions.fetch RedmineSaml::SloTokenStore::ACTION

    assert_equal 10, options[:max_instances]
    assert_equal 5.minutes, options[:validity_time].call
    assert_operator RedmineSaml::SloTokenStore::ACTION.length, :<=, 30
  end

  test 'atomically consumes one exact transaction Token and rejects replay' do
    token = RedmineSaml::SloTokenStore.create_transaction @user
    context = pending_context token

    assert RedmineSaml::SloTokenStore.consume_transaction(context)
    assert_not Token.exists?(token.id)
    assert_not RedmineSaml::SloTokenStore.consume_transaction(context)
  end

  test 'rejects a transaction Token digest or user mismatch' do
    token = RedmineSaml::SloTokenStore.create_transaction @user
    context = pending_context token

    assert_nil RedmineSaml::SloTokenStore.valid_transaction(context.merge('token_verifier' => '0' * 64))
    assert_nil RedmineSaml::SloTokenStore.valid_transaction(context.merge('user_id' => users(:users_002).id))
    assert Token.exists?(token.id)
  end

  test 'consumes only the exact Redmine session Token' do
    target_value = @user.generate_session_token
    other_value = @user.generate_session_token
    target = RedmineSaml::SloTokenStore.session_token user_id: @user.id, value: target_value
    other = RedmineSaml::SloTokenStore.session_token user_id: @user.id, value: other_value
    context = RedmineSaml::SloContext.active(
      user_id: @user.id,
      token: target,
      name_id: @user.mail,
      session_index: '_session-index',
      settings: @settings
    )

    valid_token = RedmineSaml::SloTokenStore.valid_session context
    assert_equal target, valid_token
    assert RedmineSaml::SloTokenStore.consume_session(context, valid_token)
    assert_not Token.exists?(target.id)
    assert Token.exists?(other.id)
  end

  test 'keeps Redmine session semantics when session verification is disabled' do
    original_verify_sessions = Rails.application.config.redmine_verify_sessions
    Rails.application.config.redmine_verify_sessions = false
    value = @user.generate_session_token
    token = RedmineSaml::SloTokenStore.session_token user_id: @user.id, value: value
    token.update_column :created_on, 1.year.ago
    token.reload
    context = RedmineSaml::SloContext.active(
      user_id: @user.id,
      token: token,
      name_id: @user.mail,
      session_index: '_session-index',
      settings: @settings
    )
    User.expects(:verify_session_token).never

    assert_equal token, RedmineSaml::SloTokenStore.valid_session(context)
  ensure
    Rails.application.config.redmine_verify_sessions = original_verify_sessions
  end

  private

  def pending_context(token)
    RedmineSaml::SloContext.pending(
      transaction_id: '_transaction-id',
      user_id: @user.id,
      token: token,
      login: @user.login,
      settings: @settings
    )
  end
end
