# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SudoReauthTest < RedmineSaml::TestCase
  fixtures :users

  # Minimal stand-in for OmniAuth::Strategies::SAML during the setup phase.
  # It represents this plugin's own SAML provider unless told otherwise.
  class StrategyDouble
    attr_reader :options, :request, :callback_path, :script_name

    def initialize(on_callback_path:, relay_state: nil, in_response_to: :none,
                   callback_path: RedmineSaml::CALLBACK_PATH, script_name: '')
      @on_callback_path = on_callback_path
      @callback_path = callback_path
      @script_name = script_name
      @options = {}
      @request = RequestDouble.new relay_state, saml_response(in_response_to)
    end

    def on_callback_path?
      @on_callback_path
    end

    def on_request_path?
      false
    end

    private

    # An unsigned Response is enough here: the setup phase only decodes it to
    # read the InResponseTo, and ruby-saml validates nothing at that point.
    def saml_response(in_response_to)
      return if in_response_to == :none

      RedmineSaml::SamlResponseBuilder.encoded signed: false, in_response_to: in_response_to
    end
  end

  # Stands in for the memoized Rack::Request of the strategy.
  class RequestDouble
    attr_reader :params

    def initialize(relay_state, saml_response = nil)
      @params = {}
      @params['RelayState'] = relay_state unless relay_state.nil?
      @params['SAMLResponse'] = saml_response unless saml_response.nil?
    end
  end

  # Raises instead of exposing params, to prove that a Sudo callback candidate
  # fails closed rather than continuing unvalidated.
  class BrokenRequestDouble
    def params
      raise 'broken request'
    end
  end

  setup do
    prepare_tests
    # SAML Sudo re-authentication follows Redmine's own Sudo Mode, which the
    # test configuration keeps off, so it is turned on for these tests.
    Redmine::SudoMode.stubs(:enabled?).returns true
    RedmineSaml::SudoTokenStore.register_action!
    @user = users :users_001
    @settings = RedmineSaml.configured_saml
  end

  teardown do
    User.current = nil
  end

  test 'follows Redmine Sudo Mode on every supported Redmine release' do
    assert RedmineSaml::SudoReauth.enabled?

    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns false

    assert_not RedmineSaml::SudoReauth.enabled?
  end

  test 'is a complete no-op while Redmine Sudo Mode is off' do
    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns false
    User.current = @user
    pending = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context,
                logged_in_with_saml: true }

    assert_not RedmineSaml::SudoReauth.available?(session: pending)
    assert_not RedmineSaml::SudoReauth.pending?(session: pending)
    assert_not RedmineSaml::SudoReauth.callback?(env: { RedmineSaml::SudoReauth::ENV_CALLBACK => true },
                                                 session: pending)
    assert_not RedmineSaml::SudoReauth.failure_message?(RedmineSaml::SudoReauth::FAILURE_MESSAGE)

    strategy, env = sudo_marker_setup session: pending
    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }
    assert_not strategy.options.key?(:matches_request_id)
    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]

    request_strategy, = real_strategy path: '/auth/saml', session: pending
    request_strategy.send :setup_phase

    assert pending[RedmineSaml::SudoReauth::SESSION_KEY],
           'nothing may be cancelled while Sudo Mode is off'
  end

  test 'builds and reads a RelayState that stays within the SAML 80 byte limit' do
    nonce = RedmineSaml::SudoReauth.generate_nonce
    relay_state = RedmineSaml::SudoReauth.relay_state nonce

    assert relay_state.start_with?(RedmineSaml::SudoReauth::RELAY_STATE_MARKER)
    assert_operator relay_state.bytesize, :<=, 80
    assert_equal nonce, RedmineSaml::SudoReauth.relay_state_nonce(relay_state)
  end

  test 'generates a distinct high entropy nonce per transaction' do
    nonces = Array.new(5) { RedmineSaml::SudoReauth.generate_nonce }

    assert_equal 5, nonces.uniq.size
    nonces.each { |nonce| assert_equal RedmineSaml::SudoReauth::NONCE_BYTES * 2, nonce.length }
  end

  test 'does not read a Sudo nonce out of a foreign RelayState' do
    assert_nil RedmineSaml::SudoReauth.relay_state_nonce(nil)
    assert_nil RedmineSaml::SudoReauth.relay_state_nonce('')
    assert_nil RedmineSaml::SudoReauth.relay_state_nonce('/projects')
    assert_nil RedmineSaml::SudoReauth.relay_state_nonce(RedmineSaml::SudoReauth::RELAY_STATE_MARKER)
  end

  test 'treats a callback as Sudo from the setup phase verdict or the session' do
    classified = { RedmineSaml::SudoReauth::ENV_CALLBACK => true }
    pending = { RedmineSaml::SudoReauth::SESSION_KEY => { 'type' => 'sudo' } }

    assert RedmineSaml::SudoReauth.callback?(env: classified, session: {})
    assert RedmineSaml::SudoReauth.callback?(env: {}, session: pending)
    assert RedmineSaml::SudoReauth.callback?(env: classified, session: pending)
    assert_not RedmineSaml::SudoReauth.callback?(env: {}, session: {})
    assert_not RedmineSaml::SudoReauth.callback?(env: nil, session: nil)
  end

  test 'never classifies a callback from request parameters outside the setup phase' do
    marker = RedmineSaml::SudoReauth.relay_state RedmineSaml::SudoReauth.generate_nonce

    # A RelayState that only Rails would see is not a classification signal:
    # the setup phase reads Rack parameters and is the single authority.
    assert_not RedmineSaml::SudoReauth.callback?(env: { 'RelayState' => marker }, session: {})
  end

  test 'reports a pending transaction only from the session' do
    pending = { RedmineSaml::SudoReauth::SESSION_KEY => { 'type' => 'sudo' } }

    assert RedmineSaml::SudoReauth.pending?(session: pending)
    assert_not RedmineSaml::SudoReauth.pending?(session: {})
  end

  test 'returns the one active transaction without consuming or changing it' do
    context = pending_context
    session = { RedmineSaml::SudoReauth::SESSION_KEY => context.deep_dup }
    token = RedmineSaml::SudoTokenStore.valid_transaction context

    active = RedmineSaml::SudoReauth.active_transaction(
      session: session,
      settings: @settings,
      user_id: @user.id
    )

    assert_equal context, active
    assert_equal context, session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_equal token.id, RedmineSaml::SudoTokenStore.valid_transaction(context)&.id
  end

  test 'does not follow a foreign expired malformed or consumed transaction' do
    context = pending_context
    session = { RedmineSaml::SudoReauth::SESSION_KEY => context }

    assert_nil RedmineSaml::SudoReauth.active_transaction(
      session: session,
      settings: @settings,
      user_id: users(:users_002).id
    )

    assert_nil RedmineSaml::SudoReauth.active_transaction(
      session: session,
      settings: @settings,
      user_id: @user.id,
      now: RedmineSaml::SudoContext::VALIDITY.from_now + 1.second
    )

    malformed = { RedmineSaml::SudoReauth::SESSION_KEY => context.merge('type' => 'not-sudo') }
    assert_nil RedmineSaml::SudoReauth.active_transaction(
      session: malformed,
      settings: @settings,
      user_id: @user.id
    )

    assert RedmineSaml::SudoTokenStore.consume_transaction(context)
    assert_nil RedmineSaml::SudoReauth.active_transaction(
      session: session,
      settings: @settings,
      user_id: @user.id
    )
  end

  test 'is available only for an enabled SAML session with Sudo Mode on' do
    User.current = @user
    saml_session = { logged_in_with_saml: true }

    assert RedmineSaml::SudoReauth.available?(session: saml_session)
    assert_not RedmineSaml::SudoReauth.available?(session: {}),
               'a local login session keeps the standard Redmine password prompt'

    change_saml_settings saml_enabled: 0
    assert_not RedmineSaml::SudoReauth.available?(session: saml_session)
  end

  test 'is unavailable when Redmine Sudo Mode is off or nobody is signed in' do
    User.current = @user
    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns(false)

    assert_not RedmineSaml::SudoReauth.available?(session: { logged_in_with_saml: true })

    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    User.current = User.anonymous

    assert_not RedmineSaml::SudoReauth.available?(session: { logged_in_with_saml: true })
  end

  test 'setup endpoint arms InResponseTo validation only for a pending Sudo callback' do
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
    assert_equal '_authn-request-id', RedmineSaml::SudoReauth.validated_request_id(env)
  end

  test 'setup endpoint snapshots the SAML session identifiers before omniauth-saml overwrites them' do
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy,
                    session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context,
                               'saml_uid' => 'previous-name-id',
                               'saml_session_index' => '_previous-session-index' }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    snapshot = RedmineSaml::SudoReauth.previous_saml_session env
    assert_equal 'previous-name-id', snapshot['saml_uid']
    assert_equal '_previous-session-index', snapshot['saml_session_index']
  end

  test 'setup endpoint snapshots absent SAML session identifiers as nil' do
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    snapshot = RedmineSaml::SudoReauth.previous_saml_session env
    assert snapshot, 'the snapshot must exist so the keys can be removed again'
    assert_nil snapshot['saml_uid']
    assert_nil snapshot['saml_session_index']
  end

  test 'setup endpoint leaves a normal login callback completely untouched' do
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: {}

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }

    assert_not strategy.options.key?(:matches_request_id)
    assert_nil RedmineSaml::SudoReauth.validated_request_id(env)
    assert_nil RedmineSaml::SudoReauth.previous_saml_session(env)
    assert_equal %w[omniauth.strategy rack.session], env.keys.sort
  end

  test 'setup endpoint ignores the request, metadata and Single Logout phases' do
    strategy = StrategyDouble.new on_callback_path: false,
                                  relay_state: RedmineSaml::SudoReauth.relay_state('deadbeef')
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }

    assert_not strategy.options.key?(:matches_request_id)
    assert_nil RedmineSaml::SudoReauth.validated_request_id(env)
    assert_nil RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'setup endpoint fails a Sudo marker without any transaction closed' do
    strategy, env = sudo_marker_setup session: {}

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails a Sudo marker with a consumed transaction closed' do
    session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    session.delete RedmineSaml::SudoReauth::SESSION_KEY
    strategy, env = sudo_marker_setup session: session

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails an expired transaction closed' do
    expired = pending_context now: RedmineSaml::SudoContext::VALIDITY.ago - 1.minute
    strategy, env = sudo_marker_setup session: { RedmineSaml::SudoReauth::SESSION_KEY => expired }

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails a malformed transaction closed' do
    %w[type version].each do |broken_key|
      damaged = pending_context.merge broken_key => 'broken'
      strategy, env = sudo_marker_setup session: { RedmineSaml::SudoReauth::SESSION_KEY => damaged }

      assert_raise RedmineSaml::SudoReauth::CallbackRejected, broken_key do
        RedmineSaml::SudoReauth.prepare_callback_validation env
      end
      assert_not strategy.options.key?(:matches_request_id), broken_key
    end
  end

  test 'setup endpoint fails an expired transaction closed without a RelayState marker' do
    expired = pending_context now: RedmineSaml::SudoContext::VALIDITY.ago - 1.minute
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => expired }

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
  end

  test 'setup endpoint still arms a pending transaction when the RelayState was stripped' do
    strategy = StrategyDouble.new on_callback_path: true, relay_state: nil
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
    assert RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'setup endpoint fails closed when it breaks after detecting a Sudo callback' do
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    RedmineSaml::SudoContext.stubs(:load_context).raises(RuntimeError, 'unexpected setup failure')

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
    assert RedmineSaml::SudoReauth.previous_saml_session(env),
           'the snapshot is taken before anything that can fail'
  end

  test 'setup endpoint keeps existing behaviour when a normal login callback breaks' do
    strategy = StrategyDouble.new on_callback_path: true
    strategy.instance_variable_set :@request, BrokenRequestDouble.new
    env = setup_env strategy, session: {}

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint never raises for a non SAML callback middleware state' do
    broken = Object.new
    env = { 'omniauth.strategy' => broken, 'rack.session' => nil }

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }
    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation({}) }
  end

  test 'reports its stable OmniAuth failure message' do
    assert_equal 'redmine_saml_sudo_reauth', RedmineSaml::SudoReauth::FAILURE_MESSAGE
    assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE,
                 RedmineSaml::SudoReauth::CallbackRejected.new.message
    assert RedmineSaml::SudoReauth.failure_message?(RedmineSaml::SudoReauth::FAILURE_MESSAGE)
    assert_not RedmineSaml::SudoReauth.failure_message?('invalid_ticket')
    assert_not RedmineSaml::SudoReauth.failure_message?(nil)
  end

  # ---------------------------------------------------------------------------
  # OmniAuth setup_phase extension and the deployment's own :setup
  # ---------------------------------------------------------------------------

  test 'never takes over the OmniAuth setup option of the deployment' do
    assert_not RedmineSaml.configured_saml.key?(:setup),
               'the provider options must stay exactly what the initializer configured'
    assert_not RedmineSaml.configured_saml.key?('setup')
  end

  test 'extends OmniAuth setup_phase on every supported Redmine release' do
    assert OmniAuth::Strategies::SAML.include?(RedmineSaml::SudoReauth::SetupPhase)
    assert_not RedmineSaml::SudoReauth.install_setup_phase!,
               'installing the extension twice must be a no-op'
  end

  test 'runs a callable deployment setup first and keeps its option changes' do
    calls = []
    deployment_setup = lambda do |env|
      calls << :deployment_setup
      env['omniauth.strategy'].options[:idp_entity_id] = 'dynamic-value'
    end
    strategy, env = real_strategy setup: deployment_setup,
                                  session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    strategy.send :setup_phase

    assert_equal [:deployment_setup], calls
    assert_equal 'dynamic-value', strategy.options[:idp_entity_id],
                 'a dynamic option change of the deployment must survive'
    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
    assert RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'keeps the call-through form of the deployment setup' do
    seen = []
    strategy, = real_strategy setup: true,
                              session: {},
                              app: lambda { |env|
                                seen << [env['PATH_INFO'], env['REQUEST_METHOD']]
                                [200, {}, []]
                              }

    strategy.send :setup_phase

    assert_equal [['/auth/saml/setup', 'GET']], seen
  end

  test 'keeps a custom setup_path of the deployment' do
    seen = []
    strategy, = real_strategy setup: true,
                              setup_path: '/deployment/saml/setup',
                              session: {},
                              app: lambda { |env|
                                seen << [env['PATH_INFO'], env['REQUEST_METHOD']]
                                [200, {}, []]
                              }

    strategy.send :setup_phase

    assert_equal [['/deployment/saml/setup', 'GET']], seen
  end

  test 'never swallows an error raised by the deployment setup' do
    deployment_setup = ->(_env) { raise 'deployment setup failure' }
    strategy, env = real_strategy setup: deployment_setup,
                                  session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    error = assert_raise RuntimeError do
      strategy.send :setup_phase
    end

    assert_equal 'deployment setup failure', error.message
    assert_not strategy.options.key?(:matches_request_id),
               'the Sudo processing must not run after the deployment setup failed'
    assert_nil RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'still fails a Sudo callback closed after the deployment setup succeeded' do
    calls = []
    strategy, = real_strategy setup: ->(_env) { calls << :deployment_setup },
                              session: {},
                              relay_state: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef')

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      strategy.send :setup_phase
    end

    assert_equal [:deployment_setup], calls
  end

  test 'leaves a SAML provider of another plugin alone' do
    strategy, env = real_strategy name: 'other_saml',
                                  path: '/auth/other_saml/callback',
                                  session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context },
                                  relay_state: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef')

    assert_nothing_raised { strategy.send :setup_phase }

    assert_not strategy.options.key?(:matches_request_id)
    assert_nil RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'recognises its own callback under a relative URL root' do
    strategy, = real_strategy script_name: '/redmine',
                              session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    assert_equal '/redmine/auth/saml/callback', strategy.callback_path
    strategy.send :setup_phase

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
  end

  test 'never arms or classifies outside the callback phase of its own provider' do
    %w[/auth/saml /auth/saml/metadata /auth/saml/sls].each do |path|
      strategy, env = real_strategy path: path,
                                    session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

      assert_nothing_raised { strategy.send :setup_phase }

      assert_not strategy.options.key?(:matches_request_id), path
      assert_nil RedmineSaml::SudoReauth.previous_saml_session(env), path
      assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK], path
    end
  end

  test 'leaves the metadata and Single Logout phases of its own provider untouched' do
    %w[/auth/saml/metadata /auth/saml/sls].each do |path|
      session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
      strategy, = real_strategy path: path, session: session

      strategy.send :setup_phase

      assert session[RedmineSaml::SudoReauth::SESSION_KEY], path
      assert_equal 1, sudo_transaction_count, path
    end
  end

  # ---------------------------------------------------------------------------
  # Request phase cancellation
  # ---------------------------------------------------------------------------

  test 'cancels a pending transaction when a normal SAML login request starts' do
    session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    strategy, = real_strategy path: '/auth/saml', session: session

    strategy.send :setup_phase

    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_equal 0, sudo_transaction_count,
                 'the server side transaction Token has to go with the session state'
  end

  test 'keeps the request registry when a normal SAML login request cancels a transaction' do
    session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'
    strategy, = real_strategy path: '/auth/saml', session: session

    strategy.send :setup_phase

    assert RedmineSaml::SudoTokenStore.request_registered?('_authn-request-id'),
           'a Response for the cancelled transaction must still be recognised as Sudo'
  end

  test 'cancels nothing for the request phase of a SAML provider of another plugin' do
    session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    strategy, = real_strategy name: 'other_saml', path: '/auth/other_saml', session: session

    strategy.send :setup_phase

    assert session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_equal 1, sudo_transaction_count
  end

  test 'survives a request phase without a usable session' do
    strategy, = real_strategy path: '/auth/saml', session: {}

    assert_nothing_raised { strategy.send :setup_phase }
  end

  # ---------------------------------------------------------------------------
  # Sudo request registry classification
  # ---------------------------------------------------------------------------

  test 'classifies a callback as Sudo from the request registry alone' do
    RedmineSaml::SudoTokenStore.register_request @user, '_registered-request-id'
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: '_registered-request-id'
    env = setup_env strategy, session: {}

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert env[RedmineSaml::SudoReauth::ENV_CALLBACK]
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'keeps classifying a Sudo Response after its transaction was consumed' do
    context = pending_context
    RedmineSaml::SudoTokenStore.register_request @user, '_authn-request-id'
    assert RedmineSaml::SudoTokenStore.consume_transaction(context)
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: '_authn-request-id'
    env = setup_env strategy, session: {}

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  test 'stops classifying a Sudo Response once the request registry expired' do
    RedmineSaml::SudoTokenStore.register_request @user, '_registered-request-id'
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: '_registered-request-id'
    env = setup_env strategy, session: {}

    travel_to RedmineSaml::SudoTokenStore::REQUEST_VALIDITY.from_now + 1.minute do
      assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }
    end

    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  test 'never classifies an unrelated login callback from the request registry' do
    RedmineSaml::SudoTokenStore.register_request @user, '_registered-request-id'
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: '_a-normal-login-request'
    env = setup_env strategy, session: {}

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }

    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'never classifies an IdP initiated login without an InResponseTo' do
    RedmineSaml::SudoTokenStore.register_request @user, '_registered-request-id'
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: nil
    env = setup_env strategy, session: {}

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }

    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  test 'never rejects a normal login just because the request registry is unavailable' do
    strategy = StrategyDouble.new on_callback_path: true, in_response_to: '_registered-request-id'
    env = setup_env strategy, session: {}
    RedmineSaml::SudoTokenStore.stubs(:request_registered?).raises(RuntimeError, 'registry down')

    assert_nothing_raised { RedmineSaml::SudoReauth.prepare_callback_validation env }

    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'still fails a Sudo callback closed when the request registry is unavailable' do
    RedmineSaml::SudoTokenStore.stubs(:request_registered?).raises(RuntimeError, 'registry down')

    # A pending session transaction and a RelayState marker are both signals
    # that need neither the registry nor the Response.
    _marker_strategy, env = sudo_marker_setup session: {}
    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert env[RedmineSaml::SudoReauth::ENV_CALLBACK]

    expired = pending_context now: RedmineSaml::SudoContext::VALIDITY.ago - 1.minute
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => expired }
    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  test 'reads the InResponseTo of a real Response with ruby-saml only' do
    RedmineSaml::SudoTokenStore.register_request @user, '_a-real-authn-request'
    strategy, env = real_strategy session: {},
                                  saml_response: RedmineSaml::SamlResponseBuilder.encoded(
                                    in_response_to: '_a-real-authn-request'
                                  )

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      strategy.send :setup_phase
    end
    assert env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  test 'never classifies a Response that ruby-saml cannot even decode' do
    strategy, env = real_strategy session: {}, saml_response: 'not-a-saml-response'

    assert_nothing_raised { strategy.send :setup_phase }

    assert_not env[RedmineSaml::SudoReauth::ENV_CALLBACK]
  end

  private

  # A real OmniAuth::Strategies::SAML, so that the prepended setup_phase and
  # OmniAuth's own setup semantics are exercised together.
  def real_strategy(session:, path: RedmineSaml::CALLBACK_PATH, script_name: '', name: 'saml',
                    setup: nil, setup_path: nil, relay_state: nil, saml_response: nil,
                    app: ->(_env) { [200, {}, []] })
    options = RedmineSaml.configured_saml.to_h.symbolize_keys
    options[:name] = name
    options[:setup] = setup unless setup.nil?
    options[:setup_path] = setup_path if setup_path
    strategy = OmniAuth::Strategies::SAML.new app, options

    params = {}
    params[RedmineSaml::SudoReauth::RELAY_STATE_PARAM] = relay_state if relay_state
    params[RedmineSaml::SudoReauth::SAML_RESPONSE_PARAM] = saml_response if saml_response
    env = Rack::MockRequest.env_for "#{script_name}#{path}", method: 'POST', params: params
    env['SCRIPT_NAME'] = script_name
    env['PATH_INFO'] = path
    env['rack.session'] = session
    env['omniauth.strategy'] = strategy
    strategy.instance_variable_set :@env, env
    [strategy, env]
  end

  def sudo_marker_setup(session:)
    strategy = StrategyDouble.new on_callback_path: true,
                                  relay_state: RedmineSaml::SudoReauth.relay_state(RedmineSaml::SudoReauth.generate_nonce)
    [strategy, setup_env(strategy, session: session)]
  end

  def setup_env(strategy, session:)
    { 'omniauth.strategy' => strategy, 'rack.session' => session }
  end

  def sudo_transaction_count
    Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
  end

  def pending_context(now: Time.current)
    RedmineSaml::SudoContext.build(
      user_id: @user.id,
      request_id: '_authn-request-id',
      nonce: RedmineSaml::SudoReauth.generate_nonce,
      token: RedmineSaml::SudoTokenStore.create_transaction(@user),
      return_url: '/projects',
      saml_uid: nil,
      saml_session_index: nil,
      settings: @settings,
      now: now
    )
  end
end
