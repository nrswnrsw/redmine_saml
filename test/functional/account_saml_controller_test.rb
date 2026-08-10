# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'base64'
require 'cgi'
require 'openssl'
require 'uri'

# let's use the existing functional test so we don't have to re-setup everything
# + we are sure that existing tests pass each time we run this file only
require Rails.root.join('test/functional/account_controller_test')

class AccountSamlControllerTest < RedmineSaml::ControllerTest
  TEST_IDP_ENTITY_ID = 'https://idp.example.test/metadata'
  TEST_SLS_URL = 'http://test.host/auth/saml/sls'

  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  tests AccountController

  setup do
    @saved_saml_configuration = RedmineSaml.configured_saml.deep_dup
    prepare_tests
    configure_slo_test
  end

  teardown do
    RedmineSaml.configured_saml.replace @saved_saml_configuration
  end

  context 'GET /login SAML button' do
    should "show up only if there's a plugin setting for SAML URL" do
      change_saml_settings saml_enabled: 0
      get :login
      assert_response :success
      assert_select '#saml-login', 0

      change_saml_settings saml_enabled: 1
      get :login
      assert_select '#saml-login'
    end
  end

  context 'GET login_with_saml_redirect' do
    should 'redirect to /login without starting SAML authentication when SAML is disabled' do
      change_saml_settings saml_enabled: 0

      get :login_with_saml_redirect,
          params: { provider: 'saml' }

      assert_redirected_to '/login'
      assert_nil session[:user_id]
      assert_not session[:logged_in_with_saml]
      assert_equal User.anonymous, User.current
    end
  end

  context 'GET login_with_saml_callback' do
    should 'refuse an existing user without creating a session when SAML is disabled' do
      change_saml_settings saml_enabled: 0
      request.env['omniauth.auth'] = { 'saml_login' => 'admin' }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/login'
      assert_nil session[:user_id]
      assert_not session[:logged_in_with_saml]
      assert_equal User.anonymous, User.current
    end

    should 'authenticate an active existing user with the Redmine session lifecycle' do
      request.env['omniauth.auth'] = { 'saml_login' => 'admin' }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/my/page'
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
      assert_equal users(:users_001), User.current
    end

    should 'update the Sudo Mode timestamp after successful SAML login' do
      started_at = Time.now.to_i
      request.env['omniauth.auth'] = { 'saml_login' => 'admin' }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/my/page'
      assert_operator session[:sudo_timestamp], :>=, started_at
      assert_operator session[:sudo_timestamp], :<=, Time.now.to_i
    end

    should 'redirect to /login after failed login' do
      request.env['omniauth.auth'] = { 'saml_login' => 'non-existent' }
      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/login'
    end

    should 'set a boolean in session to keep track of login' do
      request.env['omniauth.auth'] = { 'saml_login' => 'admin' }
      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/my/page'
      assert session[:logged_in_with_saml]
    end

    should 'preserve the OmniAuth SAML session identifiers across the Redmine session reset' do
      session['saml_uid'] = users(:users_001).mail
      session['saml_session_index'] = '_saml-session-index'
      request.env['omniauth.auth'] = { 'saml_login' => 'admin' }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/my/page'
      assert session[:logged_in_with_saml]
      assert_equal users(:users_001).mail, session['saml_uid']
      assert_equal '_saml-session-index', session['saml_session_index']
    end

    should 'reject a locked user without updating login state' do
      user = users :users_005
      last_login_on = user.last_login_on
      request.env['omniauth.auth'] = { 'saml_login' => user.login }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/login'
      assert_equal I18n.t(:notice_account_locked), flash[:error]
      assert_equal last_login_on, user.reload.last_login_on
      assert_saml_session_deleted
    end

    should 'reject a registered user without updating login state' do
      user = users :users_002
      user.update_column :status, User::STATUS_REGISTERED
      last_login_on = user.last_login_on
      request.env['omniauth.auth'] = { 'saml_login' => user.login }

      with_settings self_registration: '2' do
        get :login_with_saml_callback,
            params: { provider: 'saml' }
      end

      assert_redirected_to '/login'
      assert_equal I18n.t(:notice_account_pending), flash[:error]
      assert_equal last_login_on, user.reload.last_login_on
      assert_saml_session_deleted
    end

    should 'render an error for an inactive user in replace mode without redirecting to login' do
      change_saml_settings replace_redmine_login: 1
      user = users :users_005
      request.env['omniauth.auth'] = { 'saml_login' => user.login }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_response :forbidden
      assert_select '#content', text: /#{Regexp.escape I18n.t(:notice_account_locked)}/
      assert_saml_session_deleted
    end

    should 'redirect to Home if not logged in with SAML' do
      get :logout
      assert_redirected_to home_url
    end

    should 'show the Redmine logout confirmation without starting SLO on GET' do
      establish_saml_session

      get :logout

      assert_response :success
      assert_saml_session_active
    end

    should 'locally log out before redirecting to SAML logout on the Redmine POST logout' do
      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='
      RedmineSaml.configured_saml[:idp_slo_service_url] = 'https://saml.server/ls/?wa=wsignout1'
      establish_saml_session
      session['saml_uid'] = '_opaque-idp-name-id'
      expected_name_id = session['saml_uid']
      expected_session_index = session['saml_session_index']

      post :logout

      assert_response :redirect
      assert_match(/#{Regexp.escape RedmineSaml.configured_saml[:idp_slo_service_url]}.*http%3A%2F%2Ftest\.host%2F/,
                   @response.redirect_url)
      assert session[:transaction_id].present?
      assert session[:saml_logout_pending]
      request_params = Rack::Utils.parse_query URI.parse(@response.redirect_url).query
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new request_params['SAMLRequest']
      assert_equal expected_name_id, logout_request.name_id
      assert_equal session[:transaction_id], logout_request.id
      assert_equal [expected_session_index], logout_request.session_indexes
      assert_saml_session_deleted
    end

    should 'locally log out when the SP LogoutRequest cannot be generated' do
      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='
      RedmineSaml.configured_saml[:idp_slo_service_url] = nil
      establish_saml_session

      post :logout

      assert_redirected_to home_path
      assert_saml_session_deleted
    end

    should 'keep legacy full-certificate login and local logout without idp_entity_id' do
      RedmineSaml.configured_saml.delete :idp_entity_id
      assert RedmineSaml.enabled?

      get :login_with_saml_redirect, params: { provider: 'saml' }
      assert_redirected_to RedmineSaml.configured_saml[:idp_sso_service_url]

      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='
      establish_saml_session
      post :logout

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'keep legacy fingerprint login and local logout without idp_entity_id' do
      configure_fingerprint_only_slo
      RedmineSaml.configured_saml.delete :idp_entity_id
      assert RedmineSaml.enabled?

      get :login_with_saml_redirect, params: { provider: 'saml' }
      assert_redirected_to RedmineSaml.configured_saml[:idp_sso_service_url]

      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='
      establish_saml_session
      post :logout

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'keep the local logout when a fingerprint-only Redirect LogoutResponse is rejected' do
      configure_fingerprint_only_slo
      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='
      establish_saml_session

      post :logout
      transaction_id = session[:transaction_id]
      assert_saml_session_deleted

      get :redirect_after_saml_logout,
          params: signed_logout_response_params(request_id: transaction_id)

      assert_response :bad_request
      assert_saml_session_deleted
    end
  end

  context 'SAML Single Logout service' do
    setup do
      establish_saml_session
    end

    should 'keep the session when a plain GET has no SAML message' do
      get :redirect_after_saml_logout

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'keep the session when HEAD carries a LogoutRequest' do
      head :redirect_after_saml_logout, params: signed_logout_request_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'not log out a Redmine password session with a valid SAML LogoutRequest' do
      session.delete :logged_in_with_saml
      session.delete 'saml_uid'

      get :redirect_after_saml_logout, params: signed_logout_request_params

      assert_response :bad_request
      assert_equal users(:users_001).id, session[:user_id]
      assert_not session[:logged_in_with_saml]
      assert_equal users(:users_001), User.current
    end

    should 'reject an unsigned LogoutRequest without deleting the session' do
      logout_params = signed_logout_request_params
      logout_params.delete 'Signature'
      logout_params.delete 'SigAlg'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a LogoutRequest with an invalid signature without deleting the session' do
      logout_params = signed_logout_request_params
      logout_params['Signature'] = Base64.strict_encode64 'invalid signature'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a signed LogoutRequest for another Destination without deleting the session' do
      logout_params = signed_logout_request_params destination: 'https://unexpected.example.test/sls'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a signed LogoutRequest from another issuer without deleting the session' do
      logout_params = signed_logout_request_params issuer: 'https://unexpected.example.test/metadata'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'accept a signed LogoutRequest issuer when idp_entity_id is not configured' do
      RedmineSaml.configured_saml.delete :idp_entity_id
      logout_params = signed_logout_request_params

      get :redirect_after_saml_logout, params: logout_params

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'reject a LogoutRequest without an issuer when idp_entity_id is not configured' do
      RedmineSaml.configured_saml.delete :idp_entity_id
      logout_params = signed_logout_request_params issuer: nil

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a LogoutRequest for another SAML session index' do
      logout_params = signed_logout_request_params session_index: '_another-session-index'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject an indexed LogoutRequest when the local SAML session index is unavailable' do
      session.delete 'saml_session_index'
      logout_params = signed_logout_request_params session_index: '_current-session-index'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a LogoutRequest for another NameID' do
      logout_params = signed_logout_request_params name_id: 'another-user@example.test'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'process a valid IdP initiated LogoutRequest with a matching configured issuer' do
      logout_params = signed_logout_request_params
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new logout_params['SAMLRequest']

      get :redirect_after_saml_logout, params: logout_params

      assert_response :redirect
      response_params = Rack::Utils.parse_query URI.parse(@response.redirect_url).query
      logout_response = OneLogin::RubySaml::Logoutresponse.new response_params['SAMLResponse']
      assert_equal logout_request.id, logout_response.in_response_to
      assert_saml_session_deleted
    end

    should 'accept a Redirect LogoutRequest signed with the IdP raw percent encoding' do
      logout_params, raw_query = differently_encoded_redirect_query signed_logout_request_params,
                                                                    'SAMLRequest'

      get_saml_logout_with_raw_query logout_params, raw_query

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'reject a LogoutResponse whose InResponseTo does not match the SP request' do
      session[:transaction_id] = '_expected-request-id'
      logout_params = signed_logout_response_params request_id: '_different-request-id'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a LogoutResponse with an invalid signature without deleting the session' do
      session[:transaction_id] = '_expected-request-id'
      logout_params = signed_logout_response_params request_id: session[:transaction_id]
      logout_params['Signature'] = Base64.strict_encode64 'invalid signature'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a LogoutResponse when there is no SP transaction ID' do
      logout_params = signed_logout_response_params request_id: '_request-id'

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'process a valid SP initiated LogoutResponse and delete the session' do
      session[:transaction_id] = '_expected-request-id'
      logout_params = signed_logout_response_params request_id: session[:transaction_id]

      get :redirect_after_saml_logout, params: logout_params

      assert_redirected_to home_path
      assert_saml_session_deleted
    end

    should 'accept a Redirect LogoutResponse signed with the IdP raw percent encoding' do
      session[:transaction_id] = '_expected-request-id'
      logout_params, raw_query = differently_encoded_redirect_query(
        signed_logout_response_params(request_id: session[:transaction_id]),
        'SAMLResponse'
      )

      get_saml_logout_with_raw_query logout_params, raw_query

      assert_redirected_to home_path
      assert_saml_session_deleted
    end

    should 'not validate the alternate encoding signature after decoded parameters are re-encoded' do
      logout_params, raw_query, signed_query = differently_encoded_redirect_query(
        signed_logout_request_params,
        'SAMLRequest',
        include_signed_query: true
      )
      normalized_query = OneLogin::RubySaml::Utils.build_query(
        type: 'SAMLRequest',
        data: logout_params['SAMLRequest'],
        relay_state: logout_params['RelayState'],
        sig_alg: logout_params['SigAlg']
      )
      signature = Base64.strict_decode64 logout_params['Signature']
      digest = OpenSSL::Digest.new 'SHA256'

      assert_equal logout_params, Rack::Utils.parse_query(raw_query)
      assert_not_equal normalized_query, signed_query
      assert self.class.slo_test_private_key.public_key.verify(digest, signature, signed_query)
      assert_not self.class.slo_test_private_key.public_key.verify(digest, signature, normalized_query)
      assert_match(/%[0-9a-f]{2}/, raw_query)
    end

    should 'reject a duplicate SAMLRequest query parameter without deleting the session' do
      assert_duplicate_redirect_parameter_rejected 'SAMLRequest', message_type: 'SAMLRequest'
    end

    should 'reject a duplicate SAMLResponse query parameter without deleting the session' do
      assert_duplicate_redirect_parameter_rejected 'SAMLResponse', message_type: 'SAMLResponse'
    end

    should 'reject a duplicate RelayState query parameter without deleting the session' do
      assert_duplicate_redirect_parameter_rejected 'RelayState', message_type: 'SAMLRequest'
    end

    should 'reject a duplicate SigAlg query parameter without deleting the session' do
      assert_duplicate_redirect_parameter_rejected 'SigAlg', message_type: 'SAMLRequest'
    end

    should 'reject a duplicate Signature query parameter without deleting the session' do
      assert_duplicate_redirect_parameter_rejected 'Signature', message_type: 'SAMLRequest'
    end

    should 'validate a pending SP LogoutResponse after the local session was already deleted' do
      RedmineSaml.configured_saml[:signout_url] = 'https://saml.server/logout?return='

      post :logout
      transaction_id = session[:transaction_id]
      assert session[:saml_logout_pending]
      assert_saml_session_deleted

      get :redirect_after_saml_logout,
          params: signed_logout_response_params(request_id: transaction_id)

      assert_redirected_to home_path
      assert_nil session[:transaction_id]
      assert_not session[:saml_logout_pending]
      assert_saml_session_deleted
    end

    should 'validate a signed POST LogoutRequest without requiring a Rails CSRF token' do
      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_request_params(
               binding: :post,
               session_index: session['saml_session_index']
             )
      end

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'validate a signed POST LogoutResponse before deleting the session' do
      session[:transaction_id] = '_expected-request-id'

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_response_params(request_id: session[:transaction_id], binding: :post)
      end

      assert_redirected_to home_path
      assert_saml_session_deleted
    end

    should 'accept a fingerprint-only POST LogoutRequest with a matching unexpired certificate' do
      configure_fingerprint_only_slo
      RedmineSaml.configured_saml.delete :idp_entity_id

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_request_params(
               binding: :post,
               session_index: session['saml_session_index']
             )
      end

      assert_response :redirect
      assert_saml_session_deleted
    end

    should 'accept a fingerprint-only POST LogoutResponse with a matching unexpired certificate' do
      configure_fingerprint_only_slo
      session[:transaction_id] = '_expected-request-id'

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_response_params(request_id: session[:transaction_id], binding: :post)
      end

      assert_redirected_to home_path
      assert_saml_session_deleted
    end

    should 'reject a fingerprint-only Redirect LogoutRequest without deleting the session' do
      configure_fingerprint_only_slo

      get :redirect_after_saml_logout,
          params: signed_logout_request_params

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a fingerprint-only POST LogoutRequest when the fingerprint does not match' do
      configure_fingerprint_only_slo
      RedmineSaml.configured_saml[:idp_cert_fingerprint] = Array.new(20, '00').join ':'

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_request_params(
               binding: :post,
               session_index: session['saml_session_index']
             )
      end

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject a fingerprint-only POST LogoutRequest with an expired certificate' do
      certificate = self.class.expired_slo_test_certificate
      configure_fingerprint_only_slo certificate

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_request_params(
               binding: :post,
               certificate: certificate,
               session_index: session['saml_session_index']
             )
      end

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject an unsigned POST LogoutRequest without deleting the session' do
      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_request_params(
               binding: :post,
               session_index: session['saml_session_index'],
               signed: false
             )
      end

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject an unsigned POST LogoutResponse without deleting the session' do
      session[:transaction_id] = '_expected-request-id'

      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: signed_logout_response_params(
               request_id: session[:transaction_id],
               binding: :post,
               signed: false
             )
      end

      assert_response :bad_request
      assert_saml_session_active
    end

    should 'reject an invalid POST before logout without invoking the Redmine CSRF failure handler' do
      with_forgery_protection do
        post :redirect_after_saml_logout,
             params: { SAMLRequest: Base64.strict_encode64('<invalid/>') }
      end

      assert_response :bad_request
      assert_saml_session_active
    end
  end

  class << self
    def slo_test_private_key
      @slo_test_private_key ||= OpenSSL::PKey::RSA.new 2048
    end

    def slo_test_certificate
      @slo_test_certificate ||= begin
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = 1
        name = OpenSSL::X509::Name.parse '/CN=redmine-saml-test-idp'
        certificate.subject = name
        certificate.issuer = name
        certificate.public_key = slo_test_private_key.public_key
        certificate.not_before = Time.now.utc - 3600
        certificate.not_after = Time.now.utc + 86_400
        digest = OpenSSL::Digest.new 'SHA256'
        certificate.sign slo_test_private_key, digest
        certificate
      end
    end

    def expired_slo_test_certificate
      @expired_slo_test_certificate ||= begin
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = 2
        certificate.serial = 2
        name = OpenSSL::X509::Name.parse '/CN=expired-redmine-saml-test-idp'
        certificate.subject = name
        certificate.issuer = name
        certificate.public_key = slo_test_private_key.public_key
        certificate.not_before = Time.now.utc - 7200
        certificate.not_after = Time.now.utc - 3600
        digest = OpenSSL::Digest.new 'SHA256'
        certificate.sign slo_test_private_key, digest
        certificate
      end
    end
  end

  private

  def configure_slo_test
    config = RedmineSaml.configured_saml
    config[:idp_entity_id] = TEST_IDP_ENTITY_ID
    config[:idp_cert] = self.class.slo_test_certificate.to_pem
    config.delete :idp_cert_fingerprint
    config[:single_logout_service_url] = TEST_SLS_URL
    config[:name_identifier_value] = 'mail'
  end

  def configure_fingerprint_only_slo(certificate = self.class.slo_test_certificate)
    fingerprint = OpenSSL::Digest::SHA1.hexdigest(certificate.to_der).scan(/../).join ':'
    config = RedmineSaml.configured_saml
    config.delete :idp_cert
    config.delete :idp_cert_multi
    config[:idp_cert_fingerprint] = fingerprint
    config[:security] = config.fetch(:security, {}).merge(check_idp_cert_expiration: true)
  end

  def incoming_slo_settings(destination: TEST_SLS_URL,
                            issuer: TEST_IDP_ENTITY_ID,
                            name_id: users(:users_001).mail,
                            session_index: nil,
                            binding: :redirect,
                            signed: true,
                            certificate: self.class.slo_test_certificate)
    OneLogin::RubySaml::Settings.new.tap do |settings|
      settings.idp_slo_service_url = destination
      settings.idp_slo_service_binding = binding
      settings.sp_entity_id = issuer
      settings.name_identifier_value = name_id
      settings.name_identifier_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
      settings.sessionindex = session_index
      if signed
        settings.certificate = certificate.to_pem
        settings.private_key = self.class.slo_test_private_key.to_pem
      end
      settings.compress_request = false if binding == :post
      settings.compress_response = false if binding == :post
      settings.security[:logout_requests_signed] = signed
      settings.security[:logout_responses_signed] = signed
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.security[:digest_method] = XMLSecurity::Document::SHA256
    end
  end

  def signed_logout_request_params(**options)
    OneLogin::RubySaml::Logoutrequest.new.create_params(
      incoming_slo_settings(**options),
      'RelayState' => home_url
    )
  end

  def signed_logout_response_params(request_id:, **options)
    OneLogin::RubySaml::SloLogoutresponse.new.create_params(
      incoming_slo_settings(**options),
      request_id,
      nil,
      'RelayState' => home_url
    )
  end

  def differently_encoded_redirect_query(params, message_type, include_signed_query: false)
    decoded_params = params.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
    signed_components = [
      "#{message_type}=#{alternate_percent_encode(decoded_params.fetch(message_type))}",
      "RelayState=#{alternate_percent_encode(decoded_params.fetch('RelayState'))}",
      "SigAlg=#{alternate_percent_encode(decoded_params.fetch('SigAlg'))}"
    ]
    signed_query = signed_components.join '&'
    digest = OpenSSL::Digest.new 'SHA256'
    signature = self.class.slo_test_private_key.sign digest, signed_query
    decoded_params['Signature'] = Base64.strict_encode64 signature
    raw_query = "#{signed_query}&Signature=#{alternate_percent_encode decoded_params['Signature']}"

    result = [decoded_params, raw_query]
    result << signed_query if include_signed_query
    result
  end

  def alternate_percent_encode(value)
    CGI.escape(value.to_s)
       .gsub(/%[0-9A-F]{2}/, &:downcase)
       .sub('test.host', 'test%2ehost')
  end

  def get_saml_logout_with_raw_query(decoded_params, raw_query)
    request.query_string = raw_query
    get :redirect_after_saml_logout, params: decoded_params
  end

  def assert_duplicate_redirect_parameter_rejected(parameter, message_type:)
    if message_type == 'SAMLResponse'
      session[:transaction_id] = '_expected-request-id'
      params = signed_logout_response_params request_id: session[:transaction_id]
    else
      params = signed_logout_request_params
    end
    decoded_params, raw_query = differently_encoded_redirect_query params, message_type
    duplicate_component = raw_query.split('&').find do |component|
      Rack::Utils.unescape(component.split('=', 2).first) == parameter
    end

    assert duplicate_component
    get_saml_logout_with_raw_query decoded_params, "#{raw_query}&#{duplicate_component}"

    assert_response :bad_request
    assert_saml_session_active
  end

  def establish_saml_session
    user = users :users_001
    session[:user_id] = user.id
    session[:logged_in_with_saml] = true
    session['saml_uid'] = user.mail
    session['saml_session_index'] = '_current-session-index'
    User.current = user
  end

  def assert_saml_session_active
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
    assert_equal users(:users_001), User.current
  end

  def assert_saml_session_deleted
    assert_nil session[:user_id]
    assert_not session[:logged_in_with_saml]
    assert_equal User.anonymous, User.current
  end

  def with_forgery_protection
    original = ActionController::Base.allow_forgery_protection
    ActionController::Base.allow_forgery_protection = true
    yield
  ensure
    ActionController::Base.allow_forgery_protection = original
  end
end
