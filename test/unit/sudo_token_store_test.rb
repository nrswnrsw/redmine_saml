# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SudoTokenStoreTest < RedmineSaml::TestCase
  fixtures :users

  # The request registry once evicted by count at five entries per user, which
  # dropped entries that were still within REQUEST_VALIDITY. Tests below have
  # to cross that old boundary rather than stop at it.
  PREVIOUS_COUNT_LIMIT = 5

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

  # ---------------------------------------------------------------------------
  # One transaction per Redmine login session
  # ---------------------------------------------------------------------------
  #
  # The scope of a Sudo transaction is one login session, not one user: two
  # browsers or devices of the same user each get their own, and neither may
  # drop the other's. Within one login session there is exactly one, and which
  # request gets it is decided by the unique index on tokens.value.

  test 'gives one login session exactly one transaction' do
    session = login_session 'tk-a'

    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, session
    second = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    assert first, 'the first request has to acquire the transaction'
    assert_nil second, 'a second request of the same login session must not acquire one'
    assert Token.exists?(first.id)
    assert_equal 1, sudo_transaction_count
  end

  test 'lets the database refuse the second transaction of one login session' do
    session = login_session 'tk-a'
    RedmineSaml::SudoTokenStore.acquire_transaction @user, session
    value = RedmineSaml::SudoSession.lock_value session,
                                                length: RedmineSaml::SudoTokenStore::LOCK_VALUE_LENGTH

    # The refusal comes from the unique index rather than from a check, which
    # is what makes it hold for genuinely concurrent requests as well.
    #
    # The violation is raised inside a savepoint of its own, exactly as
    # acquire_transaction raises it: on PostgreSQL a constraint violation
    # aborts the transaction it happens in and every later statement in it is
    # refused, which would otherwise break the transactional fixtures of this
    # very test rather than only this insert.
    assert_raises ActiveRecord::RecordNotUnique do
      Token.transaction requires_new: true do
        Token.insert!({ user_id: @user.id, action: RedmineSaml::SudoTokenStore::ACTION,
                        value: value, created_on: Time.current, updated_on: Time.current })
      end
    end

    assert_equal 1, sudo_transaction_count, 'the surrounding transaction has to stay usable'
  end

  # The regression the PostgreSQL matrix caught: a refused acquisition used to
  # leave the surrounding transaction aborted, so every statement after it
  # failed with PG::InFailedSqlTransaction. Nothing here is PostgreSQL
  # specific, but on PostgreSQL these statements are what actually break.
  test 'keeps the surrounding transaction usable after a refused acquisition' do
    session = login_session 'tk-a'
    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    second = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    assert_nil second, 'the second acquisition has to be refused'

    # Every one of these would raise PG::InFailedSqlTransaction if the unique
    # violation had aborted the transaction this test runs in.
    assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
    assert Token.exists?(first.id)
    assert_not RedmineSaml::SudoTokenStore.transaction_pending?(login_session('tk-b'))
    assert RedmineSaml::SudoTokenStore.transaction_pending?(session)
    registry = RedmineSaml::SudoTokenStore.register_request @user, '_after-a-refused-acquisition'
    assert registry.persisted?
    assert RedmineSaml::SudoTokenStore.consume_transaction(build_context(first))
    assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count

    # And the login session can acquire again afterwards.
    assert RedmineSaml::SudoTokenStore.acquire_transaction(@user, session)
  end

  test 'keeps the surrounding transaction usable after a refused concurrent acquisition' do
    session = login_session 'tk-a'
    raced = false
    competitor = nil

    RedmineSaml::SudoTokenStore.stubs(:expire_lock).with do
      unless raced
        raced = true
        competitor = RedmineSaml::SudoTokenStore.acquire_transaction @user, session
      end
      true
    end

    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    assert raced
    assert_equal 1, [first, competitor].compact.size
    assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count,
                 'the loser must not have poisoned the transaction of the winner'
  end

  test 'lets only one of two concurrent acquisitions of one login session win' do
    session = login_session 'tk-a'
    competitor = nil
    raced = false

    # A deterministic race window instead of a sleep: the competing request
    # runs its whole acquisition after this one has looked at the table and
    # before it inserts. That is exactly the interleaving a check against the
    # session cookie cannot survive, because both requests read the same
    # cookie snapshot and both would pass it.
    RedmineSaml::SudoTokenStore.stubs(:expire_lock).with do
      unless raced
        raced = true
        competitor = RedmineSaml::SudoTokenStore.acquire_transaction @user, session
      end
      true
    end

    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    assert raced, 'the race window must have been entered'
    assert_equal 1, [first, competitor].compact.size,
                 'exactly one of two concurrent acquisitions may win'
    assert_equal 1, sudo_transaction_count
  end

  test 'keeps the transactions of two login sessions of one user independent' do
    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, login_session('tk-a')
    second = RedmineSaml::SudoTokenStore.acquire_transaction @user, login_session('tk-b')

    assert first
    assert second, 'another login session of the same user must get its own transaction'
    assert Token.exists?(first.id), 'a second login session must not drop the first transaction'
    assert Token.exists?(second.id)
    assert_equal 2, sudo_transaction_count
  end

  test 'lets a login session start again once its transaction expired' do
    session = login_session 'tk-a'
    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

    travel_to RedmineSaml::SudoTokenStore::TRANSACTION_VALIDITY.from_now + 1.second do
      second = RedmineSaml::SudoTokenStore.acquire_transaction @user, session

      assert second, 'an expired transaction must not wedge the login session'
      assert_not Token.exists?(first.id)
      assert_equal 1, sudo_transaction_count
    end
  end

  test 'reports whether this login session holds a transaction' do
    session = login_session 'tk-a'

    assert_not RedmineSaml::SudoTokenStore.transaction_pending?(session)

    context = build_context RedmineSaml::SudoTokenStore.acquire_transaction(@user, session)

    assert RedmineSaml::SudoTokenStore.transaction_pending?(session)
    assert_not RedmineSaml::SudoTokenStore.transaction_pending?(login_session('tk-b')),
               'another login session must not see this transaction'
    assert_not RedmineSaml::SudoTokenStore.transaction_pending?({}),
               'a session without a Redmine session token holds nothing'

    assert RedmineSaml::SudoTokenStore.consume_transaction(context)
    assert_not RedmineSaml::SudoTokenStore.transaction_pending?(session)
  end

  test 'falls back to a transaction of its own without a Redmine session token' do
    first = RedmineSaml::SudoTokenStore.acquire_transaction @user, {}
    second = RedmineSaml::SudoTokenStore.acquire_transaction @user, {}

    assert first
    assert second
    assert Token.exists?(first.id),
           'the fallback must not evict the transaction of another login session'
    assert_equal 2, sudo_transaction_count
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

  # ---------------------------------------------------------------------------
  # Sudo request registry
  # ---------------------------------------------------------------------------

  test 'registers the request registry as its own short lived Token action' do
    RedmineSaml::SudoTokenStore.register_action!
    options = Token.actions.fetch RedmineSaml::SudoTokenStore::REQUEST_ACTION

    assert_equal 5.minutes, options[:validity_time].call
    assert_operator RedmineSaml::SudoTokenStore::REQUEST_ACTION.length, :<=, 30
    assert_not_equal RedmineSaml::SudoTokenStore::ACTION, RedmineSaml::SudoTokenStore::REQUEST_ACTION
    assert_not_equal RedmineSaml::SloTokenStore::ACTION, RedmineSaml::SudoTokenStore::REQUEST_ACTION
  end

  test 'stores a request registry entry within the existing tokens schema' do
    token = RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    assert_equal RedmineSaml::SudoTokenStore::REQUEST_ACTION, token.action
    assert_equal @user.id, token.user_id
    assert_equal Token.columns_hash['value'].limit, token.reload.value.length
    assert_not_equal '_authn-request-id', token.value,
                     'only a digest of the AuthnRequest ID is stored'
    assert RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id')
  end

  test 'recognises a registered request only by its exact AuthnRequest ID' do
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    assert_not RedmineSaml::SudoTokenStore.request_registered?('_other-request-id')
    assert_not RedmineSaml::SudoTokenStore.request_registered?('_authn-request-i')
    assert_not RedmineSaml::SudoTokenStore.request_registered?(nil)
    assert_not RedmineSaml::SudoTokenStore.request_registered?('')
  end

  test 'keeps a request registry entry after its transaction was consumed' do
    context = build_context RedmineSaml::SudoTokenStore.create_transaction(@user)
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    assert RedmineSaml::SudoTokenStore.consume_transaction(context)

    assert RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id'),
           'a consumed transaction must still identify its own Responses'
  end

  test 'keeps a request registry entry after its transaction was destroyed' do
    context = build_context RedmineSaml::SudoTokenStore.create_transaction(@user)
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    assert RedmineSaml::SudoTokenStore.destroy_transaction(context)

    assert RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id')
  end

  test 'never evicts an unexpired request registry entry by count' do
    request_ids = Array.new(PREVIOUS_COUNT_LIMIT + 3) { |i| "_request-#{i}" }

    request_ids.each { |request_id| RedmineSaml::SudoTokenStore.register_request @user, request_id }

    # Deliberately a second loop: the point is that every entry survives every
    # later registration, which asserting inside the first loop cannot show.
    request_ids.each do |request_id| # rubocop:disable Style/CombinableLoops
      assert RedmineSaml::SudoTokenStore.request_registered?(request_id),
             "#{request_id} was dropped although it is still within REQUEST_VALIDITY"
    end
    assert_equal request_ids.size, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
  end

  test 'prunes only expired request registry entries of the user when registering' do
    stale = RedmineSaml::SudoTokenStore.register_request @user, '_stale-request'
    fresh = RedmineSaml::SudoTokenStore.register_request @user, '_fresh-request'
    other_user_stale = RedmineSaml::SudoTokenStore.register_request users(:users_002), '_other-user-request'
    [stale, other_user_stale].each do |token|
      token.update_column :created_on, RedmineSaml::SudoTokenStore::REQUEST_VALIDITY.ago - 1.minute
    end

    RedmineSaml::SudoTokenStore.register_request @user, '_new-request'

    assert_not Token.exists?(stale.id)
    assert Token.exists?(fresh.id)
    assert Token.exists?(other_user_stale.id), 'another user is never pruned here'
    assert RedmineSaml::SudoTokenStore.request_registered?('_fresh-request')
    assert RedmineSaml::SudoTokenStore.request_registered?('_new-request')
  end

  test 'expires a request registry entry with the transaction validity' do
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    travel_to RedmineSaml::SudoTokenStore::REQUEST_VALIDITY.from_now - 1.minute do
      assert RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id')
    end
    travel_to RedmineSaml::SudoTokenStore::REQUEST_VALIDITY.from_now + 1.minute do
      assert_not RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id')
    end
  end

  test 'lets Redmine prune expired request registry entries' do
    token = RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'
    token.update_column :created_on, RedmineSaml::SudoTokenStore::REQUEST_VALIDITY.ago - 1.minute

    Token.destroy_expired

    assert_not Token.exists?(token.id)
  end

  test 'refuses to register a request without an AuthnRequest ID' do
    assert_raise ArgumentError do
      RedmineSaml::SudoTokenStore.register_request @user, nil
    end
    assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
  end

  test 'never mistakes a transaction Token for a request registry entry' do
    transaction = RedmineSaml::SudoTokenStore.create_transaction @user
    context = build_context transaction
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'

    assert_not RedmineSaml::SudoTokenStore.request_registered?(transaction.value)
    assert RedmineSaml::SudoTokenStore.valid_transaction(context)
  end

  private

  # A Redmine login session is identified by session[:tk], the session token
  # Redmine issues in start_user_session.
  def login_session(token)
    { tk: token }
  end

  def sudo_transaction_count
    Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
  end

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
