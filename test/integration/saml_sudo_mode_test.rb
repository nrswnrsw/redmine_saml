# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'base64'
require 'rexml/document'
require 'uri'
require 'zlib'

class SamlSudoModeTest < Redmine::IntegrationTest
  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  include RedmineSaml::TestHelper

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
    skip_unless_sudo_supported
    saml_login
    expire_sudo_mode!

    post '/roles',
         params: { role: { name: 'a new role' } },
         headers: { 'HTTP_REFERER' => '/roles/new' }

    assert_response :success
    assert_select 'form#saml-sudo-reauth-form[action=?]', '/saml/sudo_reauth'
    assert_select 'input[name=sudo_password]', 0
    assert_select 'form#saml-sudo-reauth-form input[name=?][value=?]', 'back_url', '/roles/new'
    assert_includes @response.headers['Cache-Control'], 'no-store'
    assert_nil Role.find_by(name: 'a new role')
  end

  test 'offers SAML re-authentication in the modal for an XHR request' do
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
    log_user 'admin', 'admin'
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
  end

  test 'keeps the Redmine password prompt when the SAML plugin is disabled' do
    skip_unless_sudo_supported
    saml_login
    change_saml_settings saml_enabled: 0
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
  end

  test 'never changes the Sudo Mode prompt before Redmine 7.0' do
    skip 'only relevant before Redmine 7.0' if RedmineSaml::SudoReauth.supported?
    saml_login
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
  end

  test 'completes a full SAML sudo re-authentication round trip' do
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported

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
    skip_unless_sudo_supported
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
    skip_unless_sudo_supported
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
  end

  test 'asks the IdP for the same authentication conditions as the real login request phase' do
    skip_unless_sudo_supported
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

  test 'never fail-closes anything before Redmine 7.0' do
    skip 'only relevant before Redmine 7.0' if RedmineSaml::SudoReauth.supported?
    saml_login

    with_omniauth_production_mode do
      post RedmineSaml::CALLBACK_PATH,
           params: { SAMLResponse: 'not-a-saml-response',
                     RelayState: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef') }
    end

    assert_not_equal RedmineSaml::SudoReauth::FAILURE_MESSAGE, saml_failure_message,
                     'the setup endpoint must be a complete no-op before Redmine 7.0'
    assert_includes saml_failure_message, 'Malformed XML'
  end

  private

  def skip_unless_sudo_supported
    skip 'SAML sudo re-authentication requires Redmine 7.0' unless RedmineSaml::SudoReauth.supported?
  end

  def with_omniauth_production_mode
    original_test_mode = OmniAuth.config.test_mode
    OmniAuth.config.test_mode = false
    yield
  ensure
    OmniAuth.config.test_mode = original_test_mode
  end

  def saml_failure_message
    assert_response :redirect
    failure_uri = URI.parse response.location
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
