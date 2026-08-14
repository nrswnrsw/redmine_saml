# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SudoTokenStoreTest < RedmineSaml::TestCase
  fixtures :users

  setup do
    RedmineSaml::SudoTokenStore.register_action!
    @user = users :users_001
    @settings = RedmineSaml.configured_saml
  end

  test 'registers its own short lived Token action without touching the SLO action' do
    RedmineSaml::SudoTokenStore.register_action!
    options = Token.actions.fetch RedmineSaml::SudoTokenStore::ACTION

    assert_equal 1, options[:max_instances]
    assert_equal 5.minutes, options[:validity_time].call
    assert_operator RedmineSaml::SudoTokenStore::ACTION.length, :<=, 30
    assert_not_equal RedmineSaml::SloTokenStore::ACTION, RedmineSaml::SudoTokenStore::ACTION
  end

  test 'does not require a schema change to store the marker' do
    token = RedmineSaml::SudoTokenStore.create_transaction @user

    assert_equal RedmineSaml::SudoTokenStore::ACTION, token.action
    assert_equal @user.id, token.user_id
    assert token.value.present?
  end

  test 'atomically consumes one exact transaction Token and rejects replay' do
    context = build_context RedmineSaml::SudoTokenStore.create_transaction(@user)

    assert RedmineSaml::SudoTokenStore.consume_transaction(context)
    assert_not Token.exists?(context['token_id'])
    assert_not RedmineSaml::SudoTokenStore.consume_transaction(context)
  end

  test 'lets only one of two concurrent consumers win' do
    context = build_context RedmineSaml::SudoTokenStore.create_transaction(@user)
    # Both callers see the same still valid Token, exactly as two concurrent
    # callbacks would. Only the single conditional DELETE decides the winner.
    first_lookup = RedmineSaml::SudoTokenStore.valid_transaction context
    second_lookup = RedmineSaml::SudoTokenStore.valid_transaction context

    assert_equal first_lookup, second_lookup

    results = [RedmineSaml::SudoTokenStore.consume_transaction(context),
               RedmineSaml::SudoTokenStore.consume_transaction(context)]

    assert_equal [true, false], results
  end

  test 'rejects a transaction Token digest, user or timestamp mismatch' do
    token = RedmineSaml::SudoTokenStore.create_transaction @user
    context = build_context token

    assert_nil RedmineSaml::SudoTokenStore.valid_transaction(context.merge('token_verifier' => '0' * 64))
    assert_nil RedmineSaml::SudoTokenStore.valid_transaction(context.merge('user_id' => users(:users_002).id))
    assert_nil RedmineSaml::SudoTokenStore.valid_transaction(context.merge('token_created_at' => 0))
    assert_nil RedmineSaml::SudoTokenStore.valid_transaction(nil)
    assert Token.exists?(token.id)
  end

  test 'refuses to consume an expired transaction Token' do
    token = RedmineSaml::SudoTokenStore.create_transaction @user
    context = build_context token
    token.update_column :created_on, RedmineSaml::SudoTokenStore::TRANSACTION_VALIDITY.ago - 1.minute

    assert_nil RedmineSaml::SudoTokenStore.valid_transaction(context.merge('token_created_at' => token.reload.created_on.to_i))
    assert_not RedmineSaml::SudoTokenStore.consume_transaction(context)
  end

  test 'destroys a transaction Token for the cancel and failure paths' do
    token = RedmineSaml::SudoTokenStore.create_transaction @user
    context = build_context token

    assert RedmineSaml::SudoTokenStore.destroy_transaction(context)
    assert_not Token.exists?(token.id)
    assert_not RedmineSaml::SudoTokenStore.destroy_transaction(context)
    assert_not RedmineSaml::SudoTokenStore.destroy_transaction(nil)
  end

  test 'starting a new transaction supersedes the previous one for the same user' do
    first = RedmineSaml::SudoTokenStore.create_transaction @user
    second = RedmineSaml::SudoTokenStore.create_transaction @user

    assert_not Token.exists?(first.id)
    assert Token.exists?(second.id)
  end

  test 'does not consume Redmine session Tokens' do
    session_value = @user.generate_session_token
    session_token = Token.find_by user_id: @user.id, action: 'session', value: session_value
    sudo_context = build_context RedmineSaml::SudoTokenStore.create_transaction(@user)
    context = sudo_context.merge 'token_id' => session_token.id,
                                 'token_verifier' => RedmineSaml::SudoContext.digest(session_token.value),
                                 'token_created_at' => session_token.created_on.to_i

    assert_not RedmineSaml::SudoTokenStore.consume_transaction(context)
    assert Token.exists?(session_token.id)
  end

  private

  def build_context(token)
    RedmineSaml::SudoContext.build(
      user_id: @user.id,
      request_id: '_authn-request-id',
      nonce: RedmineSaml::SudoReauth.generate_nonce,
      token: token,
      return_url: '/projects',
      saml_uid: nil,
      saml_session_index: nil,
      settings: @settings
    )
  end
end
