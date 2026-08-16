# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'base64'
require 'rexml/document'
require 'uri'
require 'zlib'

class AccountSamlSudoTest < RedmineSaml::ControllerTest
  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  tests AccountController

  # Stands in for RedmineSaml::SloCookie when the atomic cookie write has to
  # fail. Rails encrypts and size checks before it touches the cookie jar, so a
  # real failure also leaves the previous cookie in place.
  class FailingSloCookie
    class WriteFailed < StandardError; end

    def write_active_payload(_payload)
      raise WriteFailed, 'slo cookie write failure'
    end
  end

  setup do
    save_saml_configuration
    prepare_tests
    RedmineSaml::SudoTokenStore.register_action!
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    @user = users :users_002
    @other_user = users :users_003
    @locked_user = users :users_005
  end

  teardown do
    restore_saml_configuration
    User.current = nil
  end

  # ---------------------------------------------------------------------------
  # Sudo Mode disabled non-regression
  # ---------------------------------------------------------------------------
  #
  # SAML Sudo re-authentication exists on every supported Redmine release and
  # is gated by Redmine's own Sudo Mode. With Sudo Mode off, Redmine never asks
  # for confirmation in the first place and nothing of this feature may run.

  test 'refuses to start a SAML sudo transaction while Sudo Mode is off' do
    with_sudo_mode_disabled do
      establish_saml_session

      assert_no_difference 'Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count' do
        post :saml_sudo_reauth, params: { back_url: '/projects' }
      end

      assert_response :forbidden
      assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
      assert_saml_login_session_intact
    end
  end

  test 'never branches a SAML callback into the sudo handler while Sudo Mode is off' do
    with_sudo_mode_disabled do
      establish_saml_session
      request.env['omniauth.auth'] = { 'saml_login' => @user.login }
      request.env[RedmineSaml::SudoReauth::ENV_CALLBACK] = true

      post :login_with_saml_callback,
           params: { provider: 'saml', RelayState: RedmineSaml::SudoReauth.relay_state('deadbeef') }

      # The normal login path ran, exactly as before this feature existed.
      assert_redirected_to '/my/page'
      assert_equal @user.id, session[:user_id]
      assert session[:logged_in_with_saml]
    end
  end

  test 'keeps the whole sudo machinery switched off while Sudo Mode is off' do
    with_sudo_mode_disabled do
      establish_saml_session

      assert_not RedmineSaml::SudoReauth.enabled?
      assert_not RedmineSaml::SudoReauth.available?(session: session)
      assert_not RedmineSaml::SudoReauth.pending?(session: session)
      assert_not RedmineSaml::SudoReauth.callback?(
        env: { RedmineSaml::SudoReauth::ENV_CALLBACK => true },
        session: { RedmineSaml::SudoReauth::SESSION_KEY => { 'type' => 'sudo' } }
      )
      RedmineSaml::SudoReauth.process_setup_phase 'omniauth.strategy' => nil, 'rack.session' => session

      assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
      assert_not AccountController.method_defined?(:render_sudo_form_without_saml),
                 'the plugin must not alias Redmine Sudo Mode methods'
    end
  end

  test 'installs the Sudo Mode prompt override on every supported Redmine release' do
    assert ApplicationController <= RedmineSaml::Patches::ApplicationControllerPatch
    assert RedmineSaml::SudoReauth.enabled?,
           'the feature follows Redmine Sudo Mode, not the Redmine version'
  end

  # ---------------------------------------------------------------------------
  # Starting a Sudo transaction
  # ---------------------------------------------------------------------------

  test 'starts a Sudo AuthnRequest with its own ID and stores the transaction' do
    establish_saml_session

    transaction = start_sudo_transaction back_url: '/projects'
    authn_request = transaction[:authn_request]

    assert_equal RedmineSaml.configured_saml[:assertion_consumer_service_url],
                 authn_request.attributes['AssertionConsumerServiceURL'],
                 'the Sudo transaction must reuse the configured ACS URL'
    assert_equal authn_request.attributes['ID'], transaction[:context]['request_id']
    assert_equal @user.id, transaction[:context]['user_id']
    assert_equal '/projects', transaction[:context]['return_url']
    assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::ACTION, user_id: @user.id).count
    assert_saml_login_session_intact
  end

  test 'asks the IdP for the same authentication conditions as a normal login' do
    establish_saml_session

    sudo_request = start_sudo_transaction[:authn_request]

    assert_equal authentication_conditions(normal_login_authn_request),
                 authentication_conditions(sudo_request),
                 'the plugin must not change any IdP authentication condition for a Sudo transaction'
  end

  test 'never sets ForceAuthn or IsPassive on either AuthnRequest' do
    establish_saml_session

    sudo_request = start_sudo_transaction[:authn_request]

    [normal_login_authn_request, sudo_request].each do |authn_request|
      assert_nil authn_request.attributes['ForceAuthn']
      assert_nil authn_request.attributes['IsPassive']
    end
  end

  test 'does not modify the configured SAML settings while starting a transaction' do
    establish_saml_session
    settings_before = RedmineSaml.configured_saml.deep_dup

    start_sudo_transaction

    assert_equal settings_before, RedmineSaml.configured_saml
  end

  test 'snapshots the SAML session identifiers when the transaction starts' do
    establish_saml_session

    context = start_sudo_transaction[:context]

    assert_equal 'current-name-id', context['saml_uid']
    assert_equal '_current-session-index', context['saml_session_index']
  end

  test 'never trusts an unsafe return URL when starting a transaction' do
    establish_saml_session

    transaction = start_sudo_transaction back_url: 'https://attacker.example/steal'

    assert_equal home_path, transaction[:context]['return_url']
  end

  test 'rejects a sudo transaction start without a CSRF token' do
    establish_saml_session

    with_forgery_protection do
      assert_no_difference 'Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count' do
        post :saml_sudo_reauth, params: { back_url: '/projects' }
      end
    end

    # The numeric status keeps this independent of the Rack version, which
    # renamed :unprocessable_entity to :unprocessable_content in Rack 3.1.
    assert_response 422 # rubocop:disable Rails/HttpStatus
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
  end

  test 'has no GET route for the sudo transaction start' do
    assert_raise ActionController::RoutingError do
      Rails.application.routes.recognize_path '/saml/sudo_reauth', method: :get
    end

    expected_route = { controller: 'account', action: 'saml_sudo_reauth' }
    assert_equal expected_route, Rails.application.routes.recognize_path('/saml/sudo_reauth', method: :post)
  end

  test 'refuses to start a sudo transaction for a local login session' do
    establish_local_session

    assert_no_difference 'Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count' do
      post :saml_sudo_reauth, params: { back_url: '/projects' }
    end

    assert_response :forbidden
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_equal @user.id, session[:user_id]
  end

  test 'refuses to start a sudo transaction when SAML is disabled or nobody is signed in' do
    establish_saml_session
    change_saml_settings saml_enabled: 0

    post :saml_sudo_reauth
    assert_response :forbidden

    change_saml_settings saml_enabled: 1
    reset_session_state
    post :saml_sudo_reauth
    assert_response :forbidden
  end

  # ---------------------------------------------------------------------------
  # Successful Sudo callback
  # ---------------------------------------------------------------------------

  test 'refreshes only the sudo timestamp and returns to the safe URL' do
    establish_saml_session
    transaction = start_sudo_transaction back_url: '/projects'
    session_user_id = session[:user_id]
    session_token = session[:tk]
    last_login_on = @user.reload.last_login_on
    started_at = Time.now.to_i
    calls = count_controller_calls :handle_active_user, :successful_authentication

    post_sudo_callback transaction

    assert_equal 0, calls[:handle_active_user]
    assert_equal 0, calls[:successful_authentication]
    assert_redirected_to '/projects'
    assert_operator session[:sudo_timestamp], :>=, started_at
    assert_operator session[:sudo_timestamp], :<=, Time.now.to_i
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
    assert session[:logged_in_with_saml]
    assert_equal last_login_on, @user.reload.last_login_on
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
  end

  test 'never runs the normal login hooks during a sudo callback' do
    establish_saml_session
    transaction = start_sudo_transaction
    hook_calls = 0

    # successful_authentication is the only caller of the Redmine
    # controller_account_success_authentication_after hook in this flow.
    calls = count_controller_calls :successful_authentication, :handle_active_user

    with_on_login_callback proc { |_omniauth, _user| hook_calls += 1 } do
      post_sudo_callback transaction
    end

    assert_response :redirect
    assert_equal 0, hook_calls, 'the SAML on_login callback must not run for a sudo transaction'
    assert_equal 0, calls[:successful_authentication]
    assert_equal 0, calls[:handle_active_user]
  end

  test 'never creates a user on the fly during a sudo callback' do
    change_saml_settings onthefly_creation: 1
    establish_saml_session
    transaction = start_sudo_transaction

    assert_no_difference 'User.count' do
      post_sudo_callback transaction, auth: { 'saml_login' => 'brand-new-saml-user',
                                              'mail' => 'brand-new@example.com',
                                              'first_name' => 'Brand',
                                              'last_name' => 'New' }
    end

    assert_sudo_rejected
  end

  test 'adopts the new NameID and SessionIndex and reissues the SLO context' do
    establish_saml_session
    transaction = start_sudo_transaction
    calls = count_controller_calls :build_active_slo_context, :commit_saml_sudo_reauth

    post_sudo_callback transaction,
                       saml_uid: 'refreshed-name-id',
                       saml_session_index: '_refreshed-session-index'

    assert_response :redirect
    assert_equal 1, calls[:build_active_slo_context]
    assert_equal 1, calls[:commit_saml_sudo_reauth]
    assert_equal 'refreshed-name-id', session['saml_uid']
    assert_equal '_refreshed-session-index', session['saml_session_index']
  end

  test 'keeps the previous NameID when the sudo Response carries none' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, saml_uid: nil, saml_session_index: '_refreshed-session-index'

    assert_response :redirect
    assert_nil flash[:error]
    assert_equal 'current-name-id', session['saml_uid'],
                 'a successful sudo re-authentication must not erase the SAML identity'
    assert_equal '_refreshed-session-index', session['saml_session_index']
  end

  test 'keeps the previous SessionIndex when the sudo Response carries none' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, saml_uid: 'refreshed-name-id', saml_session_index: nil

    assert_response :redirect
    assert_nil flash[:error]
    assert_equal 'refreshed-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
  end

  test 'keeps a session without SAML identifiers free of them' do
    establish_saml_session saml_uid: nil, saml_session_index: nil
    transaction = start_sudo_transaction

    post_sudo_callback transaction, saml_uid: nil, saml_session_index: nil

    assert_response :redirect
    assert_nil flash[:error]
    assert_not session.key?('saml_uid')
    assert_not session.key?('saml_session_index')
  end

  test 'builds the active SLO context from the identity the session keeps' do
    establish_saml_session
    transaction = start_sudo_transaction
    captured = capture_slo_context_arguments

    post_sudo_callback transaction, saml_uid: nil, saml_session_index: nil

    assert_response :redirect
    assert_equal 1, captured.size
    assert_equal 'current-name-id', captured.first[:name_id]
    assert_equal '_current-session-index', captured.first[:session_index]
    assert_equal session['saml_uid'], captured.first[:name_id],
                 'the SLO context and the live session must describe the same identity'
    assert_equal session['saml_session_index'], captured.first[:session_index]
  end

  test 'restores the previous identity when a sudo callback is rejected' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, relay_state: 'not-a-sudo-relay-state', saml_uid: nil

    assert_sudo_rejected
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
  end

  # ---------------------------------------------------------------------------
  # Success boundary
  # ---------------------------------------------------------------------------

  test 'does not grant Sudo Mode when building the SLO context fails' do
    establish_saml_session
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    session_user_id = session[:user_id]
    session_token = session[:tk]
    commits = count_controller_calls :commit_saml_sudo_reauth
    @controller.define_singleton_method(:build_active_slo_context) { raise 'SLO context failure' }

    post_sudo_callback transaction,
                       saml_uid: 'refreshed-name-id',
                       saml_session_index: '_refreshed-session-index'

    assert_sudo_rejected
    assert_equal 0, commits[:commit_saml_sudo_reauth], 'the success commit must not have started'
    assert_equal 1, session[:sudo_timestamp], 'a failed transaction must not refresh the Sudo timestamp'
    # The identifiers are rolled back, so nothing was left half committed.
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
    assert session[:logged_in_with_saml]
  end

  test 'does not grant Sudo Mode when an unexpected error breaks the preparation' do
    establish_saml_session
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    commits = count_controller_calls :commit_saml_sudo_reauth
    User.stubs(:find_from_omniauth_saml).raises(RuntimeError, 'user resolver failure')

    post_sudo_callback transaction,
                       saml_uid: 'refreshed-name-id',
                       saml_session_index: '_refreshed-session-index'

    assert_sudo_rejected
    assert_equal 0, commits[:commit_saml_sudo_reauth]
    assert_equal 1, session[:sudo_timestamp]
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
    assert session[:logged_in_with_saml]
  end

  test 'serializes the SLO context during the preparation, not during the commit' do
    establish_saml_session
    transaction = start_sudo_transaction
    dumped_during_commit = false
    @controller.define_singleton_method :commit_saml_sudo_reauth do |prepared|
      dumped_during_commit = prepared[:slo_payload].nil? && !prepared[:slo_context].nil?
      super(prepared)
    end

    post_sudo_callback transaction

    assert_response :redirect
    assert_nil flash[:error]
    assert_not dumped_during_commit, 'the commit must receive an already serialized payload'
  end

  test 'requires the pre-overwrite snapshot before it commits' do
    establish_saml_session
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    commits = count_controller_calls :commit_saml_sudo_reauth
    # Simulates a setup endpoint that armed InResponseTo without leaving a
    # snapshot, which the setup endpoint itself cannot produce.
    RedmineSaml::SudoReauth.stubs(:previous_saml_session).returns(nil)

    post_sudo_callback transaction, saml_uid: 'refreshed-name-id'

    assert_sudo_rejected
    assert_equal 0, commits[:commit_saml_sudo_reauth]
    assert_equal 1, session[:sudo_timestamp]
  end

  test 'rolls the SAML identifiers back when the SLO cookie write fails' do
    establish_saml_session
    @request.env['HTTPS'] = 'on'
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    session_user_id = session[:user_id]
    session_token = session[:tk]
    marker_token_id = transaction[:context]['token_id']
    @controller.define_singleton_method(:slo_cookie) { @slo_cookie ||= FailingSloCookie.new }

    assert_raise FailingSloCookie::WriteFailed do
      post_sudo_callback transaction,
                         saml_uid: 'refreshed-name-id',
                         saml_session_index: '_refreshed-session-index'
    end

    # The cookie write is atomic, so the previous cookie is still in place and
    # the identifiers are restored to match it again.
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
    assert_equal 1, session[:sudo_timestamp], 'the Sudo timestamp must not be refreshed'
    assert_nil read_active_slo_cookie_value
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
    assert session[:logged_in_with_saml]
    assert_not Token.exists?(marker_token_id), 'the single use marker stays consumed'
  end

  test 'writes the new SLO context and refreshes the timestamp on success over ssl' do
    establish_saml_session
    @request.env['HTTPS'] = 'on'
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    started_at = Time.now.to_i

    post_sudo_callback transaction,
                       saml_uid: 'refreshed-name-id',
                       saml_session_index: '_refreshed-session-index'

    assert_response :redirect
    assert_nil flash[:error]
    assert_equal 'refreshed-name-id', session['saml_uid']
    assert_equal '_refreshed-session-index', session['saml_session_index']
    assert_operator session[:sudo_timestamp], :>=, started_at
    written = read_active_slo_cookie_value
    assert written, 'a new active SLO context must be written'
    assert RedmineSaml::SloContext.matching_name_id?(written, 'refreshed-name-id')
    assert RedmineSaml::SloContext.matching_session_indexes?(written, ['_refreshed-session-index'])
  end

  test 'never rolls back after the success commit' do
    establish_saml_session
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    session_user_id = session[:user_id]
    session_token = session[:tk]
    started_at = Time.now.to_i
    commits = count_controller_calls :commit_saml_sudo_reauth
    # Fails after commit_saml_sudo_reauth has run.
    @controller.define_singleton_method(:redirect_to) { |*| raise 'failure after the success commit' }

    assert_raise RuntimeError do
      post_sudo_callback transaction,
                         saml_uid: 'refreshed-name-id',
                         saml_session_index: '_refreshed-session-index'
    end

    # The transaction was committed, so nothing is rolled back and the reject
    # path was never entered.
    assert_equal 1, commits[:commit_saml_sudo_reauth]
    assert_operator session[:sudo_timestamp], :>=, started_at
    assert_equal 'refreshed-name-id', session['saml_uid']
    assert_equal '_refreshed-session-index', session['saml_session_index']
    assert_nil flash[:error]
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
  end

  test 'refreshes the Sudo timestamp on a normal successful transaction' do
    establish_saml_session
    transaction = start_sudo_transaction
    session[:sudo_timestamp] = 1
    started_at = Time.now.to_i

    post_sudo_callback transaction

    assert_response :redirect
    assert_nil flash[:error]
    assert_operator session[:sudo_timestamp], :>=, started_at
    assert_operator session[:sudo_timestamp], :<=, Time.now.to_i
  end

  test 'succeeds when a transient NameID changed but the Redmine user did not' do
    establish_saml_session
    transaction = start_sudo_transaction
    started_at = Time.now.to_i

    post_sudo_callback transaction, saml_uid: 'a-completely-different-transient-name-id'

    assert_response :redirect
    assert_operator session[:sudo_timestamp], :>=, started_at
    assert_equal 'a-completely-different-transient-name-id', session['saml_uid']
  end

  # ---------------------------------------------------------------------------
  # Rejected Sudo callbacks
  # ---------------------------------------------------------------------------

  test 'rejects a sudo callback whose InResponseTo was not validated' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, validated_request_id: nil

    assert_sudo_rejected
  end

  test 'rejects a sudo callback with a mismatched InResponseTo' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, validated_request_id: '_some-other-request-id'

    assert_sudo_rejected
  end

  test 'rejects a sudo callback with a mismatched or missing RelayState nonce' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, relay_state: RedmineSaml::SudoReauth.relay_state('0' * 32)

    assert_sudo_rejected

    establish_saml_session
    other_transaction = start_sudo_transaction
    post_sudo_callback other_transaction, relay_state: nil

    assert_sudo_rejected
  end

  test 'rejects a sudo callback after the transaction expired' do
    establish_saml_session
    transaction = start_sudo_transaction
    expire_sudo_transaction transaction

    post_sudo_callback transaction

    assert_sudo_rejected
  end

  test 'rejects a replayed sudo SAML Response without falling back to the normal login' do
    establish_saml_session
    transaction = start_sudo_transaction
    post_sudo_callback transaction
    assert_response :redirect
    sudo_timestamp = session[:sudo_timestamp]
    session[:sudo_timestamp] = 1
    last_login_on = @user.reload.last_login_on
    calls = count_controller_calls :handle_active_user, :successful_authentication

    # The session state is gone, but the setup phase verdict still routes the
    # replay into the Sudo handler instead of the normal login path, whether
    # it reached that verdict from the RelayState marker or from the request
    # registry.
    post_sudo_callback transaction, relay_state: nil

    assert_sudo_rejected
    assert_equal 0, calls[:handle_active_user]
    assert_equal 0, calls[:successful_authentication]
    assert_equal 1, session[:sudo_timestamp]
    assert_not_equal sudo_timestamp, session[:sudo_timestamp]
    assert_equal last_login_on, @user.reload.last_login_on
  end

  # A callback that loses the single conditional DELETE must leave the session
  # completely alone. Another request of the same login session owns the
  # transaction and is refreshing the Sudo timestamp for it, so anything this
  # response wrote would be a stale snapshot that rolls that back.
  test 'lets only one of two sudo callbacks for the same transaction succeed' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction
    assert_response :redirect
    assert_nil flash[:error]
    sudo_timestamp = session[:sudo_timestamp]
    saml_uid = session['saml_uid']

    # Restore the session side state so only the server side marker can decide.
    session[RedmineSaml::SudoReauth::SESSION_KEY] = transaction[:context]
    post_sudo_callback transaction

    assert_response :redirect
    assert @controller.request.session_options[:skip],
           'the losing callback must not commit the session at all'
    assert_nil flash[:error], 'the losing callback must not write a flash either'
    assert_equal sudo_timestamp, session[:sudo_timestamp],
                 'the losing callback must not roll back the Sudo timestamp of the winner'
    assert_equal saml_uid, session['saml_uid']
    assert_saml_login_session_intact
    assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
  end

  test 'rejects a sudo callback for a different Redmine user without replacing the session' do
    establish_saml_session
    transaction = start_sudo_transaction

    post_sudo_callback transaction, auth: { 'saml_login' => @other_user.login }

    assert_sudo_rejected
    assert_equal @user.id, session[:user_id]
    assert_equal @user, User.current
  end

  test 'rejects a sudo callback for an unresolvable or locked user' do
    establish_saml_session
    transaction = start_sudo_transaction
    post_sudo_callback transaction, auth: { 'saml_login' => 'no-such-saml-user' }
    assert_sudo_rejected
    assert_equal @user.id, session[:user_id]

    establish_saml_session
    locked_transaction = start_sudo_transaction
    post_sudo_callback locked_transaction, auth: { 'saml_login' => @locked_user.login }
    assert_sudo_rejected
    assert_equal @user.id, session[:user_id]
  end

  test 'restores the SAML session snapshot when a sudo callback is rejected' do
    establish_saml_session
    transaction = start_sudo_transaction
    calls = count_controller_calls :build_active_slo_context, :commit_saml_sudo_reauth

    post_sudo_callback transaction,
                       auth: { 'saml_login' => @other_user.login },
                       saml_uid: 'foreign-name-id',
                       saml_session_index: '_foreign-session-index'

    assert_sudo_rejected
    assert_equal 0, calls[:commit_saml_sudo_reauth],
                 'a rejected transaction must never write the SLO cookie'
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
  end

  test 'prefers the request env snapshot over the transaction snapshot when restoring' do
    establish_saml_session
    transaction = start_sudo_transaction

    # The setup endpoint captured these before omniauth-saml overwrote the
    # session, so they win over the values stored when the transaction started.
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_CAPTURED] = true
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_UID] = 'env-snapshot-name-id'
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_SESSION_INDEX] = '_env-snapshot-session-index'

    post_sudo_callback transaction,
                       auth: { 'saml_login' => @other_user.login },
                       saml_uid: 'foreign-name-id',
                       saml_session_index: '_foreign-session-index'

    assert_sudo_rejected
    assert_equal 'env-snapshot-name-id', session['saml_uid']
    assert_equal '_env-snapshot-session-index', session['saml_session_index']
  end

  test 'removes the SAML session identifiers when the request env snapshot was empty' do
    establish_saml_session
    transaction = start_sudo_transaction

    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_CAPTURED] = true
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_UID] = nil
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_SESSION_INDEX] = nil

    post_sudo_callback transaction,
                       auth: { 'saml_login' => @other_user.login },
                       saml_uid: 'foreign-name-id',
                       saml_session_index: '_foreign-session-index'

    assert_sudo_rejected
    assert_nil session['saml_uid']
    assert_nil session['saml_session_index']
  end

  test 'keeps the new identifiers on success and never restores the env snapshot' do
    establish_saml_session
    transaction = start_sudo_transaction

    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_CAPTURED] = true
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_UID] = 'env-snapshot-name-id'
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_SESSION_INDEX] = '_env-snapshot-session-index'

    post_sudo_callback transaction,
                       saml_uid: 'refreshed-name-id',
                       saml_session_index: '_refreshed-session-index'

    assert_response :redirect
    assert_nil flash[:error]
    assert_equal 'refreshed-name-id', session['saml_uid']
    assert_equal '_refreshed-session-index', session['saml_session_index']
  end

  test 'deletes the SAML session identifiers again when the snapshot was empty' do
    establish_saml_session saml_uid: nil, saml_session_index: nil
    transaction = start_sudo_transaction

    post_sudo_callback transaction,
                       auth: { 'saml_login' => @other_user.login },
                       saml_uid: 'foreign-name-id',
                       saml_session_index: '_foreign-session-index'

    assert_sudo_rejected
    assert_nil session['saml_uid']
    assert_nil session['saml_session_index']
  end

  test 'never destroys the Redmine login session when a sudo callback is rejected' do
    establish_saml_session
    transaction = start_sudo_transaction
    session_user_id = session[:user_id]
    session_token = session[:tk]
    calls = count_controller_calls :logout_user, :saml_logout_user

    post_sudo_callback transaction, auth: { 'saml_login' => @other_user.login }

    assert_sudo_rejected
    assert_equal 0, calls[:logout_user]
    assert_equal 0, calls[:saml_logout_user]
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
    assert session[:logged_in_with_saml]
  end

  test 'never returns to an unsafe URL after a rejected sudo callback' do
    establish_saml_session
    transaction = start_sudo_transaction
    tampered = transaction[:context].merge 'return_url' => 'https://attacker.example/steal'
    session[RedmineSaml::SudoReauth::SESSION_KEY] = tampered

    post_sudo_callback transaction, auth: { 'saml_login' => @other_user.login }

    assert_redirected_to home_path
  end

  # ---------------------------------------------------------------------------
  # /auth/failure
  # ---------------------------------------------------------------------------

  test 'handles a SAML validation failure of a pending sudo transaction' do
    establish_saml_session
    transaction = start_sudo_transaction
    session['saml_uid'] = 'foreign-name-id'
    session_user_id = session[:user_id]
    calls = count_controller_calls :logout_user, :saml_logout_user

    get :login_with_saml_failure, params: { message: 'invalid_ticket' }

    assert_equal 0, calls[:logout_user]
    assert_equal 0, calls[:saml_logout_user]
    assert_redirected_to '/projects'
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal session_user_id, session[:user_id]
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_not Token.exists?(transaction[:context]['token_id'])
    assert flash[:error].present?
  end

  test 'recognises the setup endpoint failure message without any pending transaction' do
    establish_saml_session
    session_user_id = session[:user_id]
    session_token = session[:tk]
    calls = count_controller_calls :logout_user, :saml_logout_user

    get :login_with_saml_failure,
        params: { message: RedmineSaml::SudoReauth::FAILURE_MESSAGE }

    assert_response :redirect
    assert flash[:error].present?
    assert_equal 0, calls[:logout_user]
    assert_equal 0, calls[:saml_logout_user]
    assert_equal session_user_id, session[:user_id]
    assert_equal session_token, session[:tk]
    assert session[:logged_in_with_saml]
    # No overwrite happened, so the SAML identifiers stay exactly as they were.
    assert_equal 'current-name-id', session['saml_uid']
    assert_equal '_current-session-index', session['saml_session_index']
  end

  test 'keeps the existing /auth/failure behaviour without a pending sudo transaction' do
    get :login_with_saml_failure, params: { message: 'invalid_ticket' }

    assert_redirected_to '/login'
    assert_equal I18n.t(:error_saml_invalid_ticket), flash[:error]
  end

  # ---------------------------------------------------------------------------
  # Interaction with a normal SAML login
  # ---------------------------------------------------------------------------

  test 'cancels a pending sudo transaction when a normal SAML login starts' do
    establish_saml_session
    transaction = start_sudo_transaction

    get :login_with_saml_redirect, params: { provider: 'saml' }

    assert_response :success
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert_not Token.exists?(transaction[:context]['token_id'])
  end

  test 'keeps a normal SAML login callback on the normal login path' do
    establish_saml_session
    request.env['omniauth.auth'] = { 'saml_login' => @user.login }

    post :login_with_saml_callback, params: { provider: 'saml' }

    assert_redirected_to '/my/page'
    assert_equal @user.id, session[:user_id]
    assert session[:logged_in_with_saml]
    assert_nil flash[:error]
  end

  private

  # Redmine reads sudo_mode once at boot, so the setup block turns it on for
  # this whole test case and this turns it off again for a single test.
  def with_sudo_mode_disabled
    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns false
    yield
  end

  # Counts calls to controller methods during the following requests.
  #
  # Mocha expectations set on the test controller instance are not reliable
  # across a second request here, because the object's Mocha mock is replaced
  # while the request runs. A plain singleton method keeps the original
  # behaviour and records the call deterministically.
  def count_controller_calls(*method_names)
    counts = Hash.new 0
    method_names.each do |method_name|
      original = @controller.method method_name
      @controller.define_singleton_method method_name do |*args, **kwargs, &block|
        counts[method_name] += 1
        original.call(*args, **kwargs, &block)
      end
    end
    counts
  end

  # Records the NameID and SessionIndex the controller builds the active SLO
  # context from, so it can be compared with what the session keeps.
  def capture_slo_context_arguments
    captured = []
    original = @controller.method :build_active_slo_context
    @controller.define_singleton_method :build_active_slo_context do |**kwargs|
      captured << { name_id: kwargs.fetch(:name_id), session_index: kwargs.fetch(:session_index) }
      original.call(**kwargs)
    end
    captured
  end

  def establish_saml_session(user: @user, saml_uid: 'current-name-id', saml_session_index: '_current-session-index')
    reset_session_state
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token
    @request.session[:logged_in_with_saml] = true
    @request.session['saml_uid'] = saml_uid if saml_uid
    @request.session['saml_session_index'] = saml_session_index if saml_session_index
    User.current = user
  end

  def establish_local_session(user: @user)
    reset_session_state
    @request.session[:user_id] = user.id
    @request.session[:tk] = user.generate_session_token
    User.current = user
  end

  def reset_session_state
    @request.session.clear
    User.current = nil
  end

  def start_sudo_transaction(back_url: '/projects')
    post :saml_sudo_reauth, params: { back_url: back_url }
    assert_response :redirect

    location = URI.parse response.location
    query = Rack::Utils.parse_query location.query.to_s
    context = session[RedmineSaml::SudoReauth::SESSION_KEY]
    assert context.present?, 'the sudo transaction must be stored in the session'

    { context: context.to_h.deep_stringify_keys,
      relay_state: query['RelayState'],
      authn_request: decode_authn_request(query['SAMLRequest']) }
  end

  def post_sudo_callback(transaction, auth: { 'saml_login' => @user.login },
                         relay_state: :unset, validated_request_id: :unset, sudo_callback: true,
                         saml_uid: 'current-name-id', saml_session_index: '_current-session-index')
    relay_state = transaction[:relay_state] if relay_state == :unset
    validated_request_id = transaction[:context]['request_id'] if validated_request_id == :unset

    # The classification verdict of the Sudo setup_phase extension. It runs in
    # the OmniAuth middleware, which a functional test does not go through, so
    # the verdict it would have reached is installed here. SamlSudoModeTest
    # exercises the real classification.
    request.env[RedmineSaml::SudoReauth::ENV_CALLBACK] = true if sudo_callback
    # The setup endpoint snapshots the identifiers before omniauth-saml
    # overwrites them. A test that installed its own snapshot keeps it.
    capture_previous_saml_session
    # omniauth-saml overwrites both values before the controller runs.
    session['saml_uid'] = saml_uid
    session['saml_session_index'] = saml_session_index
    request.env['omniauth.auth'] = auth
    if validated_request_id
      request.env[RedmineSaml::SudoReauth::ENV_MATCHES_REQUEST_ID] = validated_request_id
    else
      request.env.delete RedmineSaml::SudoReauth::ENV_MATCHES_REQUEST_ID
    end

    post :login_with_saml_callback, params: { provider: 'saml', RelayState: relay_state }.compact
  end

  # Mirrors RedmineSaml::SudoReauth.capture_previous_saml_session, which the
  # OmniAuth setup endpoint runs before omniauth-saml replaces the identifiers.
  def capture_previous_saml_session
    return if request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_CAPTURED]

    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_UID] = session['saml_uid']
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_SESSION_INDEX] = session['saml_session_index']
    request.env[RedmineSaml::SudoReauth::ENV_PREVIOUS_SAML_CAPTURED] = true
  end

  def expire_sudo_transaction(transaction)
    expired = transaction[:context].merge(
      'issued_at' => (RedmineSaml::SudoContext::VALIDITY.ago - 1.minute).to_i
    )
    session[RedmineSaml::SudoReauth::SESSION_KEY] = expired
  end

  def assert_sudo_rejected
    assert_response :redirect
    assert flash[:error].present?, 'a rejected sudo transaction must report an error'
    assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
  end

  def assert_saml_login_session_intact
    assert_equal @user.id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  def read_active_slo_cookie_value
    serialized = cookies.encrypted[RedmineSaml::SloCookie::ACTIVE_NAME]
    return if serialized.blank?

    RedmineSaml::SloContext.load_active serialized, settings: RedmineSaml.configured_saml
  end

  # An AuthnRequest built exactly the way the normal SAML login builds it,
  # through omniauth-saml's OneLogin::RubySaml::Settings.new(options).
  def normal_login_authn_request
    settings = OneLogin::RubySaml::Settings.new RedmineSaml.configured_saml
    decode_authn_request OneLogin::RubySaml::Authrequest.new.create_params(settings)['SAMLRequest']
  end

  # The parts of an AuthnRequest that tell the IdP how to authenticate. They
  # must be identical for a normal login and for a Sudo transaction.
  def authentication_conditions(authn_request)
    namespaces = { 'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol' }
    name_id_policy = REXML::XPath.first authn_request, './samlp:NameIDPolicy', namespaces
    requested_context = REXML::XPath.first authn_request, './samlp:RequestedAuthnContext', namespaces

    { 'ForceAuthn' => authn_request.attributes['ForceAuthn'],
      'IsPassive' => authn_request.attributes['IsPassive'],
      'ProtocolBinding' => authn_request.attributes['ProtocolBinding'],
      'AttributeConsumingServiceIndex' => authn_request.attributes['AttributeConsumingServiceIndex'],
      'NameIDPolicy' => name_id_policy&.to_s,
      'RequestedAuthnContext' => requested_context&.to_s }
  end

  def decode_authn_request(encoded_request)
    inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    xml = inflater.inflate Base64.decode64(encoded_request)
    xml << inflater.finish
    REXML::Document.new(xml).root
  ensure
    inflater&.close
  end

  def with_on_login_callback(callback)
    original_callback = RedmineSaml::Base.on_login_callback
    RedmineSaml::Base.on_login(&callback)
    yield
  ensure
    RedmineSaml::Base.on_login(&original_callback)
  end
end
