# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SudoReauthTest < RedmineSaml::TestCase
  fixtures :users

  # Minimal stand-in for OmniAuth::Strategies::SAML during the setup phase.
  # It represents this plugin's own SAML provider unless told otherwise.
  class StrategyDouble
    attr_reader :options, :request, :callback_path, :script_name

    def initialize(on_callback_path:, relay_state: nil,
                   callback_path: RedmineSaml::CALLBACK_PATH, script_name: '')
      @on_callback_path = on_callback_path
      @callback_path = callback_path
      @script_name = script_name
      @options = {}
      @request = RequestDouble.new relay_state
    end

    def on_callback_path?
      @on_callback_path
    end
  end

  # Stands in for the memoized Rack::Request of the strategy.
  class RequestDouble
    attr_reader :params

    def initialize(relay_state)
      @params = relay_state.nil? ? {} : { 'RelayState' => relay_state }
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
    RedmineSaml::SudoTokenStore.register_action!
    @user = users :users_001
    @settings = RedmineSaml.configured_saml
  end

  teardown do
    User.current = nil
  end

  test 'is enabled from Redmine 7.0 and disabled on Redmine 6.x' do
    assert_equal 7, RedmineSaml::SudoReauth::MINIMUM_REDMINE_MAJOR_VERSION
    assert_equal Redmine::VERSION::MAJOR >= 7, RedmineSaml::SudoReauth.supported?
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

  test 'treats a callback as Sudo when either the RelayState or the session says so' do
    marker = RedmineSaml::SudoReauth.relay_state RedmineSaml::SudoReauth.generate_nonce
    pending = { RedmineSaml::SudoReauth::SESSION_KEY => { 'type' => 'sudo' } }
    expected = RedmineSaml::SudoReauth.supported?

    assert_equal expected, RedmineSaml::SudoReauth.callback?(session: {}, relay_state: marker)
    assert_equal expected, RedmineSaml::SudoReauth.callback?(session: pending, relay_state: nil)
    assert_equal expected, RedmineSaml::SudoReauth.callback?(session: pending, relay_state: marker)
    assert_not RedmineSaml::SudoReauth.callback?(session: {}, relay_state: nil)
    assert_not RedmineSaml::SudoReauth.callback?(session: {}, relay_state: '/projects')
  end

  test 'reports a pending transaction only from the session' do
    pending = { RedmineSaml::SudoReauth::SESSION_KEY => { 'type' => 'sudo' } }

    assert_equal RedmineSaml::SudoReauth.supported?, RedmineSaml::SudoReauth.pending?(session: pending)
    assert_not RedmineSaml::SudoReauth.pending?(session: {})
  end

  test 'is available only for an enabled SAML session with Sudo Mode on' do
    User.current = @user
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    saml_session = { logged_in_with_saml: true }

    assert_equal RedmineSaml::SudoReauth.supported?, RedmineSaml::SudoReauth.available?(session: saml_session)
    assert_not RedmineSaml::SudoReauth.available?(session: {}),
               'a local login session keeps the standard Redmine password prompt'

    change_saml_settings saml_enabled: 0
    assert_not RedmineSaml::SudoReauth.available?(session: saml_session)
  end

  test 'is unavailable when Redmine Sudo Mode is off or nobody is signed in' do
    User.current = @user
    Redmine::SudoMode.stubs(:enabled?).returns(false)

    assert_not RedmineSaml::SudoReauth.available?(session: { logged_in_with_saml: true })

    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    User.current = User.anonymous

    assert_not RedmineSaml::SudoReauth.available?(session: { logged_in_with_saml: true })
  end

  test 'setup endpoint arms InResponseTo validation only for a pending Sudo callback' do
    skip_unless_sudo_supported

    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
    assert_equal '_authn-request-id', RedmineSaml::SudoReauth.validated_request_id(env)
  end

  test 'setup endpoint snapshots the SAML session identifiers before omniauth-saml overwrites them' do
    skip_unless_sudo_supported

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
    skip_unless_sudo_supported

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
    skip_unless_sudo_supported

    strategy, env = sudo_marker_setup session: {}

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails a Sudo marker with a consumed transaction closed' do
    skip_unless_sudo_supported

    session = { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }
    session.delete RedmineSaml::SudoReauth::SESSION_KEY
    strategy, env = sudo_marker_setup session: session

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails an expired transaction closed' do
    skip_unless_sudo_supported

    expired = pending_context now: RedmineSaml::SudoContext::VALIDITY.ago - 1.minute
    strategy, env = sudo_marker_setup session: { RedmineSaml::SudoReauth::SESSION_KEY => expired }

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
    assert_not strategy.options.key?(:matches_request_id)
  end

  test 'setup endpoint fails a malformed transaction closed' do
    skip_unless_sudo_supported

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
    skip_unless_sudo_supported

    expired = pending_context now: RedmineSaml::SudoContext::VALIDITY.ago - 1.minute
    strategy = StrategyDouble.new on_callback_path: true
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => expired }

    assert_raise RedmineSaml::SudoReauth::CallbackRejected do
      RedmineSaml::SudoReauth.prepare_callback_validation env
    end
  end

  test 'setup endpoint still arms a pending transaction when the RelayState was stripped' do
    skip_unless_sudo_supported

    strategy = StrategyDouble.new on_callback_path: true, relay_state: nil
    env = setup_env strategy, session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    RedmineSaml::SudoReauth.prepare_callback_validation env

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
    assert RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'setup endpoint fails closed when it breaks after detecting a Sudo callback' do
    skip_unless_sudo_supported

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
    assert_equal RedmineSaml::SudoReauth.supported?,
                 RedmineSaml::SudoReauth.failure_message?(RedmineSaml::SudoReauth::FAILURE_MESSAGE)
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

  test 'extends OmniAuth setup_phase only from Redmine 7.0' do
    assert_equal RedmineSaml::SudoReauth.supported?,
                 OmniAuth::Strategies::SAML.include?(RedmineSaml::SudoReauth::SetupPhase)
    assert_not RedmineSaml::SudoReauth.install_setup_phase!,
               'installing the extension twice must be a no-op'
  end

  test 'runs a callable deployment setup first and keeps its option changes' do
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
    strategy, env = real_strategy name: 'other_saml',
                                  path: '/auth/other_saml/callback',
                                  session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context },
                                  relay_state: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef')

    assert_nothing_raised { strategy.send :setup_phase }

    assert_not strategy.options.key?(:matches_request_id)
    assert_nil RedmineSaml::SudoReauth.previous_saml_session(env)
  end

  test 'recognises its own callback under a relative URL root' do
    skip_unless_sudo_supported
    strategy, = real_strategy script_name: '/redmine',
                              session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

    assert_equal '/redmine/auth/saml/callback', strategy.callback_path
    strategy.send :setup_phase

    assert_equal '_authn-request-id', strategy.options[:matches_request_id]
  end

  test 'ignores the request and other phases of its own provider' do
    skip_unless_sudo_supported
    %w[/auth/saml /auth/saml/metadata /auth/saml/sls].each do |path|
      strategy, env = real_strategy path: path,
                                    session: { RedmineSaml::SudoReauth::SESSION_KEY => pending_context }

      assert_nothing_raised { strategy.send :setup_phase }

      assert_not strategy.options.key?(:matches_request_id), path
      assert_nil RedmineSaml::SudoReauth.previous_saml_session(env), path
    end
  end

  private

  # A real OmniAuth::Strategies::SAML, so that the prepended setup_phase and
  # OmniAuth's own setup semantics are exercised together.
  def real_strategy(session:, path: RedmineSaml::CALLBACK_PATH, script_name: '', name: 'saml',
                    setup: nil, setup_path: nil, relay_state: nil, app: ->(_env) { [200, {}, []] })
    options = RedmineSaml.configured_saml.to_h.symbolize_keys
    options[:name] = name
    options[:setup] = setup unless setup.nil?
    options[:setup_path] = setup_path if setup_path
    strategy = OmniAuth::Strategies::SAML.new app, options

    params = relay_state ? { RedmineSaml::SudoReauth::RELAY_STATE_PARAM => relay_state } : {}
    env = Rack::MockRequest.env_for "#{script_name}#{path}", method: 'POST', params: params
    env['SCRIPT_NAME'] = script_name
    env['PATH_INFO'] = path
    env['rack.session'] = session
    env['omniauth.strategy'] = strategy
    strategy.instance_variable_set :@env, env
    [strategy, env]
  end

  def skip_unless_sudo_supported
    skip 'SAML sudo re-authentication requires Redmine 7.0' unless RedmineSaml::SudoReauth.supported?
  end

  def sudo_marker_setup(session:)
    strategy = StrategyDouble.new on_callback_path: true,
                                  relay_state: RedmineSaml::SudoReauth.relay_state(RedmineSaml::SudoReauth.generate_nonce)
    [strategy, setup_env(strategy, session: session)]
  end

  def setup_env(strategy, session:)
    { 'omniauth.strategy' => strategy, 'rack.session' => session }
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
