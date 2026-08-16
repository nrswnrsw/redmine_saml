# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'base64'
require 'rexml/document'
require 'uri'
require 'zlib'

class SamlSudoModeTest < Redmine::IntegrationTest
  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  include RedmineSaml::TestHelper

  # The request registry once evicted by count at five entries per user, which
  # dropped entries that were still within REQUEST_VALIDITY.
  PREVIOUS_COUNT_LIMIT = 5

  setup do
    prepare_tests
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    @original_test_mode = OmniAuth.config.test_mode
    @original_mock_auth = OmniAuth.config.mock_auth[:saml]
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }
  end

  teardown do
    travel_back
    OmniAuth.config.test_mode = @original_test_mode
    OmniAuth.config.mock_auth[:saml] = @original_mock_auth
  end

  test 'offers SAML re-authentication instead of the password prompt for a SAML session' do
    saml_login
    expire_sudo_mode!

    post '/roles',
         params: { role: { name: 'a new role' } },
         headers: { 'HTTP_REFERER' => '/roles/new' }

    assert_response :success
    assert_select 'form#saml-sudo-reauth-form[action=?]', '/saml/sudo_reauth'
    assert_select 'input[name=sudo_password]', 0
    # This request carried input, so the transaction returns through the resume
    # page, which keeps the validated back URL of the original request.
    back_url = css_select('form#saml-sudo-reauth-form input[name=back_url]').first['value']
    assert_equal '/saml/sudo_resume', back_url.split('?').first
    assert_equal '/roles/new', Rack::Utils.parse_query(back_url.split('?').last)['back_url']
    assert_includes @response.headers['Cache-Control'], 'no-store'
    assert_nil Role.find_by(name: 'a new role')
  end

  test 'returns straight to the back URL when the request carried no input' do
    saml_login
    expire_sudo_mode!

    # A GET has nothing to continue, so nothing about this path changes.
    get '/settings/plugin/redmine_saml', headers: { 'HTTP_REFERER' => '/admin' }

    assert_response :success
    assert_select 'form#saml-sudo-reauth-form input[name=?][value=?]', 'back_url', '/admin'
    assert_select 'form#saml-sudo-reauth-form[data-saml-sudo-stash]', 0
  end

  test 'offers SAML re-authentication in the modal for an XHR request' do
    saml_login
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }, xhr: true

    assert_response :success
    assert_includes @response.body, 'saml-sudo-reauth-form'
    assert_includes @response.body, 'showModal'
    assert_not_includes @response.body, 'sudo_password'
    assert_nil Role.find_by(name: 'a new role')
  end

  test 'keeps the Redmine password prompt for a local login session' do
    log_user 'admin', 'admin'
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
  end

  test 'keeps the Redmine password prompt when the SAML plugin is disabled' do
    saml_login
    change_saml_settings saml_enabled: 0
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
  end

  test 'never changes anything while Redmine Sudo Mode is off' do
    with_sudo_mode_disabled do
      saml_login
      expire_sudo_mode!

      # Redmine does not ask for confirmation at all with Sudo Mode off, so the
      # protected action simply goes through.
      assert_difference 'Role.count' do
        post '/roles',
             params: { role: { name: 'a new role',
                               issues_visibility: 'all',
                               assignable: '1',
                               permissions: %w[view_calendar] } }
      end
      assert_redirected_to '/roles'
      assert_select 'form#saml-sudo-reauth-form', 0
    end
  end

  test 'completes a full SAML sudo re-authentication round trip' do
    saml_login
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }
    assert_response :success

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    assert_response :redirect
    relay_state = relay_state_from response.location

    assert relay_state.present?
    assert_equal RedmineSaml.configured_saml[:idp_sso_service_url],
                 response.location.split('?').first

    post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }

    assert_redirected_to '/roles'
    assert_nil flash[:error]

    # Sudo Mode is active again, so the original action now goes through.
    assert_difference 'Role.count' do
      post '/roles',
           params: { role: { name: 'a new role',
                             issues_visibility: 'all',
                             assignable: '1',
                             permissions: %w[view_calendar] } }
    end
    assert_redirected_to '/roles'
  end

  test 'never reaches the normal login path when a sudo response is replayed' do
    saml_login
    session_user_id = session[:user_id]
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    relay_state = relay_state_from response.location
    post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }
    assert_redirected_to '/roles'

    post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }

    assert_response :redirect
    assert_not_equal '/my/page', URI.parse(response.location).path,
                     'a replayed sudo response must not run the normal login path'
    assert_equal session_user_id, session[:user_id]
  end

  test 'does not route a normal SAML login callback into the sudo handler' do
    saml_login
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    assert_response :redirect

    # Starting a normal SAML login cancels the pending sudo transaction.
    get '/auth/saml'
    assert_response :success

    post RedmineSaml::CALLBACK_PATH

    assert_redirected_to '/my/page'
    assert_equal users(:users_001).id, session[:user_id]
  end

  # ---------------------------------------------------------------------------
  # Setup endpoint fail-closed (A)
  # ---------------------------------------------------------------------------
  #
  # These run with OmniAuth test mode disabled so that the real callback phase
  # would execute. A Response that reaches OneLogin::RubySaml fails with
  # :invalid_ticket, so a failure message of FAILURE_MESSAGE proves that the
  # setup endpoint stopped the request before OmniAuth::Strategies::SAML#
  # callback_phase, and therefore before handle_response overwrites
  # session['saml_uid'] and session['saml_session_index'].

  test 'fails a Sudo marker without a transaction closed before the callback phase' do
    saml_login
    expire_sudo_mode!

    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: 'not-a-saml-response',
                     RelayState: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef') }
    end

    assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message,
                 'the setup endpoint must reject before ruby-saml sees the Response'
    assert_saml_login_session_intact
  end

  test 'fails a replayed Sudo response closed before the callback phase' do
    saml_login
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    relay_state = relay_state_from response.location
    post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }
    assert_redirected_to '/roles'

    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: 'not-a-saml-response', RelayState: relay_state }
    end

    assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message
    assert_saml_login_session_intact
  end

  test 'fails an expired Sudo transaction closed before the callback phase' do
    saml_login
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    relay_state = relay_state_from response.location

    # Past the five minute transaction validity.
    travel_to 30.minutes.from_now
    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: 'not-a-saml-response', RelayState: relay_state }
    end

    assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message
    assert_saml_login_session_intact
  end

  # A malformed transaction entry cannot be written from an integration test,
  # so that case is covered by SudoReauthTest at the setup endpoint itself. Here
  # only the outcome of a Sudo marker without a usable transaction is asserted.
  test 'fails a Sudo marker with an unusable transaction closed' do
    saml_login
    expire_sudo_mode!

    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: 'not-a-saml-response',
                     RelayState: "#{RedmineSaml::SudoReauth::RELAY_STATE_MARKER}broken" }
    end

    assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message
    assert_saml_login_session_intact
  end

  test 'never fail-closes a normal SAML login callback in the setup endpoint' do
    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: 'not-a-saml-response' }
    end

    # The callback reached OmniAuth::Strategies::SAML#callback_phase and failed
    # there, exactly as it did before this feature existed.
    assert_not_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message,
                     'a normal login callback must never be stopped by the setup endpoint'
    assert_includes saml_failure_message, 'Malformed XML'
  end

  test 'keeps treating a callback as Sudo when the RelayState was stripped' do
    saml_login
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    assert_response :redirect

    post RedmineSaml::CALLBACK_PATH

    assert_response :redirect
    assert_not_equal '/my/page', URI.parse(response.location).path,
                     'a pending transaction must not fall back to the normal login'
    follow_redirect!
    assert_select '#errorExplanation, #flash_error, .flash.error', 1
    assert_equal users(:users_001).id, session[:user_id]
  end

  test 'leaves the metadata and Single Logout endpoints untouched' do
    saml_login
    expire_sudo_mode!

    post '/saml/sudo_reauth', params: { back_url: '/roles' }
    assert_response :redirect

    with_omniauth_production_mode do
      get RedmineSaml::METADATA_PATH
      assert_response :success
      assert_includes @response.body, 'EntityDescriptor'

      post RedmineSaml::LOGOUT_SERVICE_PATH
      assert_response :bad_request
    end

    # The pending transaction is untouched by those endpoints.
    assert_equal users(:users_001).id, session[:user_id]
    assert session[RedmineSaml::SudoReauth::SESSION_KEY].present?
    assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
    assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
  end

  test 'asks the IdP for the same authentication conditions as the real login request phase' do
    saml_login
    expire_sudo_mode!

    login_request = nil
    sudo_request = nil
    with_omniauth_production_mode do
      # The real OmniAuth request phase, reached through the plugin's own POST
      # bridge exactly as a user reaches it.
      get '/auth/saml'
      assert_response :success
      post '/auth/saml', params: { authenticity_token: bridge_authenticity_token }
      login_request = authn_request_from response.location

      post '/saml/sudo_reauth', params: { back_url: '/roles' }
      sudo_request = authn_request_from response.location
    end

    assert login_request, 'the normal login request phase must produce an AuthnRequest'
    assert sudo_request, 'the Sudo transaction must produce an AuthnRequest'
    assert_equal authentication_conditions(login_request), authentication_conditions(sudo_request),
                 'the Sudo transaction must ask the IdP for the same authentication conditions'
    assert_not_equal login_request.attributes['ID'], sudo_request.attributes['ID'],
                     'the Sudo transaction must still use its own AuthnRequest ID'
  end

  test 'never fail-closes anything while Redmine Sudo Mode is off' do
    with_sudo_mode_disabled do
      saml_login

      with_omniauth_production_mode do
        post RedmineSaml::CALLBACK_PATH,
             params: { SAMLResponse: 'not-a-saml-response',
                       RelayState: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef') }
      end

      assert_not_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message,
                       'the Sudo setup_phase extension must be a complete no-op with Sudo Mode off'
      assert_includes saml_failure_message, 'Malformed XML'
    end
  end

  # ---------------------------------------------------------------------------
  # Sudo request registry, against real signed SAML Responses
  # ---------------------------------------------------------------------------
  #
  # OmniAuth test mode replaces the whole callback phase, so it can never show
  # what ruby-saml does with a Response, and in particular not that a Response
  # without a RelayState is still recognised as a Sudo one. These run the real
  # middleware lifecycle with Responses signed by a throwaway IdP key.

  test 'never processes a consumed sudo Response as a normal login' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!
      transaction = start_real_sudo_transaction

      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: transaction[:response], RelayState: transaction[:relay_state] }
      assert_redirected_to '/roles'
      assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
      assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
      last_login_on = users(:users_001).reload.last_login_on

      # Replayed with the RelayState dropped, so nothing but the server side
      # request registry can still recognise it as a Sudo Response.
      post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: transaction[:response] }

      assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message
      assert_saml_login_session_intact
      assert_equal last_login_on, users(:users_001).reload.last_login_on,
                   'the normal login path must not have run'
    end
  end

  test 'still identifies the first sudo Response after many transactions of the same user' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!

      # The registry once evicted by count at five entries per user, which
      # dropped the first transaction here and let its Response through as a
      # normal login. Every entry is still within REQUEST_VALIDITY.
      transaction_count = PREVIOUS_COUNT_LIMIT + 3
      transactions = Array.new transaction_count do
        transaction = start_real_sudo_transaction
        post RedmineSaml::CALLBACK_PATH,
             params: { SAMLResponse: transaction[:response], RelayState: transaction[:relay_state] }
        assert_response :redirect
        transaction
      end

      transactions.each do |transaction|
        assert RedmineSaml::SudoTokenStore.request_registered?(transaction[:request_id]),
               "#{transaction[:request_id]} was dropped although it is still within REQUEST_VALIDITY"
      end

      # Posted from a browser session that holds no Sudo state at all, so only
      # the request registry can classify it.
      other_browser = open_session
      other_browser.post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: transactions.first[:response] }

      assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE,
                   saml_failure_message(other_browser.response)
      assert_nil other_browser.session[:user_id]
      assert_equal transactions.size,
                   Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
      assert_saml_login_session_intact
    end
  end

  test 'never processes a sudo Response as a normal login in another browser session' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!
      transaction = start_real_sudo_transaction

      # The transaction is never completed here. The Response is posted from a
      # browser session that never knew about it and holds no Sudo state.
      other_browser = open_session
      other_browser.post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: transaction[:response] }

      assert_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE,
                   saml_failure_message(other_browser.response)
      assert_nil other_browser.session[:user_id]
      assert_saml_login_session_intact
    end
  end

  test 'keeps a pending transaction a sudo callback without the request registry' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!
      transaction = start_real_sudo_transaction
      Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).delete_all

      post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: transaction[:response] }

      assert_response :redirect
      assert_not_equal '/my/page', URI.parse(response.location).path,
                       'the session signal alone has to keep this out of the normal login'
      assert flash[:error].present?
      assert_saml_login_session_intact
    end
  end

  test 'cancels a pending sudo transaction when a normal SAML login request starts' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!
      post '/saml/sudo_reauth', params: { back_url: '/roles' }
      assert_response :redirect
      assert session[RedmineSaml::SudoReauth::SESSION_KEY].present?
      assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count

      # The OmniAuth request phase, reached without the Rails GET bridge.
      post '/auth/saml'
      assert_response :redirect
      assert_nil session[RedmineSaml::SudoReauth::SESSION_KEY]
      assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
      assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count,
                   'the request registry entry has to outlive the cancellation'

      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: signed_response(in_response_to: authn_request_id_from(response.location)) }

      assert_redirected_to '/my/page'
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
    end
  end

  test 'keeps the SAML identity and the active SLO cookie consistent without a new NameID' do
    with_real_saml_responses do
      https!
      real_saml_login
      assert cookies[RedmineSaml::SloCookie::ACTIVE_NAME].present?
      expire_sudo_mode!

      transaction = start_real_sudo_transaction name_id: nil
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: transaction[:response], RelayState: transaction[:relay_state] }

      assert_redirected_to '/roles'
      assert_nil flash[:error]
      assert_equal RedmineSaml::SamlResponseBuilder::NAME_ID, session['saml_uid'],
                   'a successful sudo re-authentication must not erase the SAML identity'
      assert cookies[RedmineSaml::SloCookie::ACTIVE_NAME].present?
    end
  end

  test 'keeps the SessionIndex of the session when the sudo Response carries none' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!

      transaction = start_real_sudo_transaction session_index: nil, name_id: 'refreshed-name-id'
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: transaction[:response], RelayState: transaction[:relay_state] }

      assert_redirected_to '/roles'
      assert_equal 'refreshed-name-id', session['saml_uid']
      assert_equal RedmineSaml::SamlResponseBuilder::SESSION_INDEX, session['saml_session_index']
    end
  end

  # These two hold on every supported Redmine release: before 7.0 nothing of
  # the Sudo machinery exists, and from 7.0 it must not touch a normal login.

  test 'still completes a normal SP initiated SAML login' do
    with_real_saml_responses do
      get '/auth/saml'
      assert_response :success
      post '/auth/saml', params: { authenticity_token: bridge_authenticity_token }
      assert_response :redirect

      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: signed_response(in_response_to: authn_request_id_from(response.location)) }

      assert_redirected_to '/my/page'
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
    end
  end

  test 'still completes an IdP initiated SAML login while a sudo transaction exists' do
    with_real_saml_responses do
      real_saml_login
      expire_sudo_mode!
      start_real_sudo_transaction
      assert_equal 1, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
      reset!

      # No InResponseTo at all, so the request registry can never match.
      post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: signed_response }

      assert_redirected_to '/my/page'
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
    end
  end

  test 'never records a sudo request registry entry while Sudo Mode is off' do
    with_sudo_mode_disabled do
      with_real_saml_responses do
        real_saml_login

        post '/saml/sudo_reauth', params: { back_url: '/roles' }
        assert_response :forbidden

        post '/auth/saml'
        assert_response :redirect

        assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::REQUEST_ACTION).count
        assert_equal 0, Token.where(action: RedmineSaml::SudoTokenStore::ACTION).count
      end
    end
  end

  private

  # Redmine reads sudo_mode once at boot, so the setup block turns it on for
  # this whole test case and this turns it off again for a single test.
  def with_sudo_mode_disabled
    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns false
    yield
  end

  def with_omniauth_production_mode
    original_test_mode = OmniAuth.config.test_mode
    OmniAuth.config.test_mode = false
    yield
  ensure
    OmniAuth.config.test_mode = original_test_mode
  end

  def saml_failure_message(saml_response = response)
    assert_equal 302, saml_response.status
    failure_uri = URI.parse saml_response.location
    assert_equal '/auth/failure', failure_uri.path
    Rack::Utils.parse_query(failure_uri.query.to_s)['message']
  end

  def assert_saml_login_session_intact
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  def saml_login
    post RedmineSaml::CALLBACK_PATH
    assert_redirected_to '/my/page'
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  # An IdP initiated login with a real, signed Response.
  def real_saml_login
    post RedmineSaml::CALLBACK_PATH, params: { SAMLResponse: signed_response }
    assert_redirected_to '/my/page'
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  def signed_response(**options)
    RedmineSaml::SamlResponseBuilder.encoded(**options)
  end

  # Starts a Sudo transaction and builds the Response the IdP would send back
  # for exactly that AuthnRequest.
  def start_real_sudo_transaction(back_url: '/roles', **response_options)
    post '/saml/sudo_reauth', params: { back_url: back_url }
    assert_response :redirect
    request_id = authn_request_id_from response.location
    relay_state = relay_state_from response.location
    assert request_id.present?
    assert relay_state.present?

    { request_id: request_id,
      relay_state: relay_state,
      response: signed_response(in_response_to: request_id, **response_options) }
  end

  # Sudo Mode is active right after signing in; let it expire.
  def expire_sudo_mode!
    travel_to 20.minutes.from_now
  end

  def relay_state_from(location)
    query = URI.parse(location.to_s).query.to_s
    Rack::Utils.parse_query(query)['RelayState']
  end

  def bridge_authenticity_token
    css_select('#saml-request-form input[name=authenticity_token]').first&.[]('value')
  end

  def authn_request_id_from(location)
    authn_request_from(location)&.attributes&.[]('ID')
  end

  def authn_request_from(location)
    query = URI.parse(location.to_s).query.to_s
    encoded = Rack::Utils.parse_query(query)['SAMLRequest']
    return if encoded.blank?

    inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    xml = inflater.inflate Base64.decode64(encoded)
    xml << inflater.finish
    REXML::Document.new(xml).root
  ensure
    inflater&.close
  end

  # The parts of an AuthnRequest that tell the IdP how to authenticate.
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
end
