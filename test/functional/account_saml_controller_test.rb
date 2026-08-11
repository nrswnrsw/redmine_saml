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
    should 'redirect to the configured external IdP without an open redirect warning' do
      idp_sso_service_url = 'https://trusted-idp.example.test/saml/login'
      RedmineSaml.configured_saml[:idp_sso_service_url] = idp_sso_service_url
      Rails.logger.expects(:warn).with(regexp_matches(/\AOpen redirect to /)).never

      get :login_with_saml_redirect,
          params: {
            provider: 'saml',
            origin: 'https://attacker.example/origin'
          }

      assert_redirected_to idp_sso_service_url
      assert_equal 'trusted-idp.example.test', URI.parse(@response.redirect_url).host
    end

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

    should 'log SAML authentication details without ruby-saml Settings credentials' do
      auth, response, response_xml, decrypted_document, private_keys = saml_auth_hash_with_private_keys
      logged_messages = []
      Rails.logger.stubs(:info).with do |message|
        logged_messages << message
        true
      end
      request.env['omniauth.auth'] = auth

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      callback_logs = logged_messages.grep(/\Alogin_with_saml_callback: /)
      attribute_logs = logged_messages.grep(/\Auser_attributes_from_saml: /)
      assert_equal 1, callback_logs.size
      assert_equal 1, attribute_logs.size

      (callback_logs + attribute_logs).each do |message|
        assert_includes message, "response=#{response_xml.inspect}"
        assert_includes message, "decrypted_document=#{decrypted_document.to_s.inspect}"
        assert_includes message, 'DECRYPTED_ASSERTION_LOG_FIXTURE'
        assert_includes message, '_name-id-for-safe-log-test'
        assert_includes message, '_session-index-for-safe-log-test'
        assert_includes message, 'department-for-safe-log-test'
        assert_includes message, 'Engineering'
        assert_includes message, 'admin@example.test'
        assert_includes message, 'Redmine Admin'
        assert_not_includes message, 'XMLSecurity::SignedDocument'
        assert_not_includes message, 'OneLogin::RubySaml::Settings'
        private_keys.each { |private_key| assert_not_includes message, private_key }
      end

      private_keys.each { |private_key| assert_includes auth.inspect, private_key }
      assert_same response, auth[:extra][:response_object]
      assert_same decrypted_document, response.decrypted_document
      assert_equal private_keys.first, response.settings.private_key
      assert_equal private_keys.last, response.settings.sp_cert_multi[:signing].first[:private_key]
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
      request.env['omniauth.auth'] = { 'saml_login' => user.login }

      get :login_with_saml_callback,
          params: { provider: 'saml' }

      assert_redirected_to '/login'
      assert_equal I18n.t(:notice_account_locked), flash[:error]
      assert_nil user.reload.last_login_on
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
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').never
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').never
      expected_login = User.current.login
      info_logs = capture_info_logs
      session['saml_uid'] = '_opaque-idp-name-id'
      expected_name_id = session['saml_uid']
      expected_session_index = session['saml_session_index']

      post :logout

      assert_response :redirect
      assert_match(/#{Regexp.escape RedmineSaml.configured_saml[:idp_slo_service_url]}.*http%3A%2F%2Ftest\.host%2F/,
                   @response.redirect_url)
      assert session[:transaction_id].present?
      assert session[:saml_logout_pending]
      assert_equal expected_login, session[:saml_logout_login]
      assert_not_includes info_logs, "Delete session for '#{expected_login}'"
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
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').never
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').never
      expected_login = User.current.login
      info_logs = capture_info_logs

      post :logout

      assert_redirected_to home_path
      assert_saml_session_deleted
      assert_nil session[:saml_logout_login]
      assert_not_includes info_logs, "Delete session for '#{expected_login}'"
    end

    should 'locally log out without a compatibility marker when the SLO endpoint is unavailable' do
      RedmineSaml.configured_saml.delete :signout_url
      establish_saml_session
      expected_login = User.current.login
      info_logs = capture_info_logs

      post :logout

      assert_redirected_to home_path
      assert_saml_session_deleted
      assert_nil session[:saml_logout_login]
      assert_not_includes info_logs, "Delete session for '#{expected_login}'"
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
      expected_login = User.current.login
      info_logs = capture_info_logs
      Rails.logger.expects(:warn).with('SAML logout rejected: invalid LogoutResponse').once
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').once

      post :logout
      transaction_id = session[:transaction_id]
      assert_saml_session_deleted
      assert_equal expected_login, session[:saml_logout_login]

      get :redirect_after_saml_logout,
          params: signed_logout_response_params(request_id: transaction_id)

      assert_response :bad_request
      assert_saml_session_deleted
      assert_equal transaction_id, session[:transaction_id]
      assert session[:saml_logout_pending]
      assert_equal expected_login, session[:saml_logout_login]
      assert_not_includes info_logs, "Delete session for '#{expected_login}'"
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
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').never
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').never

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
      Rails.logger.expects(:warn).with('SAML logout rejected: missing SAML signature').once
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').once
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').never

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

    should 'use an IdP SLO service URL without a query for a LogoutResponse' do
      Rails.logger.expects(:warn).with(regexp_matches(/\AOpen redirect to /)).never

      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout'
    end

    should 'use an IdP SLO service URL with a query for a LogoutResponse' do
      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout?service=original'
    end

    should 'use a queryless IdP SLO response URL when the service URL is also queryless' do
      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout',
                                      response_url: 'https://idp-response.example.test/saml/logout'
    end

    should 'use a queryless IdP SLO response URL when the service URL has a query' do
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').never
      Rails.logger.expects(:warn).with(regexp_matches(/\AOpen redirect to /)).never
      info_logs = capture_info_logs

      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout?service=original',
                                      response_url: 'https://idp-response.example.test/saml/logout'

      assert_empty info_logs.grep(/\ADelete session for /)
    end

    should 'use an IdP SLO response URL with a query when the service URL is queryless' do
      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout',
                                      response_url: 'https://idp-response.example.test/saml/logout?response=original'
    end

    should 'use an IdP SLO response URL with a query when the service URL also has a query' do
      assert_idp_logout_response_url service_url: 'https://idp-slo.example.test/saml/logout?service=original',
                                      response_url: 'https://idp-response.example.test/saml/logout?response=original'
    end

    should 'sign a LogoutResponse after correcting the response endpoint query separator' do
      configure_logout_response_signing

      response_params = assert_idp_logout_response_url(
        service_url: 'https://idp-slo.example.test/saml/logout?service=original',
        response_url: 'https://idp-response.example.test/saml/logout'
      )

      assert_valid_logout_response_signature response_params
    end

    should 'preserve sp_cert_multi while signing a LogoutResponse with a response URL query' do
      configure_logout_response_signing sp_cert_multi: true

      response_params = assert_idp_logout_response_url(
        service_url: 'https://idp-slo.example.test/saml/logout',
        response_url: 'https://idp-response.example.test/saml/logout?response=original'
      )

      assert_valid_logout_response_signature response_params
    end

    should 'copy LogoutResponse settings without mutating endpoints or credentials' do
      settings = logout_response_copy_test_settings
      original_security = settings.security.deep_dup
      original_sp_cert_multi = settings.sp_cert_multi.deep_dup

      response_settings = @controller.send :saml_logout_response_settings, settings

      assert_not_equal settings.object_id, response_settings.object_id
      assert_equal 'https://idp-slo.example.test/saml/logout?service=original', settings.idp_slo_service_url
      assert_equal 'https://idp-response.example.test/saml/logout', settings.idp_slo_response_service_url
      assert_equal settings.idp_slo_response_service_url, response_settings.idp_slo_service_url
      assert_equal settings.idp_slo_response_service_url, response_settings.idp_slo_response_service_url
      assert_equal original_security, settings.security
      assert_equal original_security, response_settings.security
      assert_equal 'ORIGINAL_SP_CERTIFICATE', settings.certificate
      assert_equal 'ORIGINAL_SP_CERTIFICATE', response_settings.certificate
      assert_equal 'ORIGINAL_SP_PRIVATE_KEY', settings.private_key
      assert_equal 'ORIGINAL_SP_PRIVATE_KEY', response_settings.private_key
      assert_equal original_sp_cert_multi, settings.sp_cert_multi
      assert_equal original_sp_cert_multi, response_settings.sp_cert_multi
      assert_not settings.compress_request
      assert_not response_settings.compress_request
      assert_not settings.compress_response
      assert_not response_settings.compress_response

      settings_without_response_url = logout_response_copy_test_settings
      settings_without_response_url.idp_slo_response_service_url = ''
      response_settings_without_response_url = @controller.send(
        :saml_logout_response_settings,
        settings_without_response_url
      )
      assert_equal settings_without_response_url.idp_slo_service_url,
                   response_settings_without_response_url.idp_slo_service_url
      assert_equal '', settings_without_response_url.idp_slo_response_service_url
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
      Rails.logger.expects(:warn).with('SAML logout rejected: invalid LogoutResponse').once
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').once
      Rails.logger.expects(:error).with('IdP initiated LogoutRequest was not valid!').never

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
      session[:saml_logout_pending] = true
      session[:saml_logout_login] = 'pending-login-must-not-be-logged'
      expected_login = User.current.login
      info_logs = capture_info_logs
      logout_params = signed_logout_response_params request_id: session[:transaction_id]
      Rails.logger.expects(:error).with('The SAML Logout Response is invalid').never

      get :redirect_after_saml_logout, params: logout_params

      assert_redirected_to home_path
      assert_saml_session_deleted
      assert_equal ["Delete session for '#{expected_login}'"], info_logs.grep(/\ADelete session for /)
      assert_nil session[:transaction_id]
      assert_not session[:saml_logout_pending]
      assert_nil session[:saml_logout_login]
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
      expected_login = User.current.login
      delete_session_log = "Delete session for '#{expected_login}'"
      info_logs = capture_info_logs

      post :logout
      transaction_id = session[:transaction_id]
      assert session[:saml_logout_pending]
      assert_equal expected_login, session[:saml_logout_login]
      assert_saml_session_deleted
      assert_not_includes info_logs, delete_session_log

      logout_params = signed_logout_response_params request_id: transaction_id

      get :redirect_after_saml_logout,
          params: logout_params

      assert_redirected_to home_path
      assert_equal [delete_session_log], info_logs.grep(/\ADelete session for /)
      assert_nil session[:transaction_id]
      assert_not session[:saml_logout_pending]
      assert_nil session[:saml_logout_login]
      assert_saml_session_deleted

      get :redirect_after_saml_logout, params: logout_params

      assert_response :bad_request
      assert_equal [delete_session_log], info_logs.grep(/\ADelete session for /)
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

  def capture_info_logs
    messages = []
    Rails.logger.stubs(:info).with do |message|
      messages << message
      true
    end
    messages
  end

  def configure_slo_test
    config = RedmineSaml.configured_saml
    config[:idp_entity_id] = TEST_IDP_ENTITY_ID
    config[:idp_cert] = self.class.slo_test_certificate.to_pem
    config.delete :idp_cert_fingerprint
    config[:single_logout_service_url] = TEST_SLS_URL
    config[:name_identifier_value] = 'mail'
  end

  def assert_idp_logout_response_url(service_url:, response_url: nil,
                                      relay_state: 'https://attacker.example/after-logout?next=/admin')
    config = RedmineSaml.configured_saml
    config[:idp_slo_service_url] = service_url
    if response_url
      config[:idp_slo_response_service_url] = response_url
    else
      config.delete :idp_slo_response_service_url
    end
    original_config = config.deep_dup
    original_config_id = config.object_id
    expected_url = response_url || service_url
    logout_params = signed_logout_request_params relay_state: relay_state
    logout_request = OneLogin::RubySaml::SloLogoutrequest.new logout_params['SAMLRequest']

    get :redirect_after_saml_logout, params: logout_params

    assert_response :redirect
    response_uri = URI.parse @response.redirect_url
    expected_uri = URI.parse expected_url
    assert_equal expected_uri.scheme, response_uri.scheme
    assert_equal expected_uri.host, response_uri.host
    assert_equal expected_uri.path, response_uri.path
    separator = expected_uri.query.present? ? '&' : '?'
    assert_includes @response.redirect_url, "#{expected_url}#{separator}SAMLResponse="
    response_params = Rack::Utils.parse_query response_uri.query
    Rack::Utils.parse_query(expected_uri.query.to_s).each do |key, value|
      assert_equal value, response_params[key]
    end
    assert response_params['SAMLResponse'].present?
    assert_equal relay_state, response_params['RelayState']
    assert_not_equal URI.parse(relay_state).host, response_uri.host
    logout_response = OneLogin::RubySaml::Logoutresponse.new response_params['SAMLResponse']
    assert_equal expected_url, logout_response.document.root.attributes['Destination']
    assert_equal logout_request.id, logout_response.in_response_to
    assert_equal original_config_id, RedmineSaml.configured_saml.object_id
    assert_equal original_config, RedmineSaml.configured_saml
    assert_saml_session_deleted

    response_params
  end

  def configure_logout_response_signing(sp_cert_multi: false)
    config = RedmineSaml.configured_saml
    config[:security] = config.fetch(:security, {}).merge(
      logout_responses_signed: true,
      signature_method: XMLSecurity::Document::RSA_SHA256,
      digest_method: XMLSecurity::Document::SHA256
    )
    certificate = self.class.slo_test_certificate.to_pem
    private_key = self.class.slo_test_private_key.to_pem

    if sp_cert_multi
      config.delete :certificate
      config.delete :private_key
      config[:sp_cert_multi] = {
        signing: [{ certificate: certificate, private_key: private_key }]
      }
    else
      config[:certificate] = certificate
      config[:private_key] = private_key
      config.delete :sp_cert_multi
    end
  end

  def assert_valid_logout_response_signature(response_params)
    assert_equal XMLSecurity::Document::RSA_SHA256, response_params['SigAlg']
    assert response_params['Signature'].present?
    signed_query = OneLogin::RubySaml::Utils.build_query(
      type: 'SAMLResponse',
      data: response_params['SAMLResponse'],
      relay_state: response_params['RelayState'],
      sig_alg: response_params['SigAlg']
    )
    signature = Base64.strict_decode64 response_params['Signature']
    digest = OpenSSL::Digest.new 'SHA256'

    assert self.class.slo_test_private_key.public_key.verify(digest, signature, signed_query)
  end

  def logout_response_copy_test_settings
    OneLogin::RubySaml::Settings.new.tap do |settings|
      settings.idp_slo_service_url = 'https://idp-slo.example.test/saml/logout?service=original'
      settings.idp_slo_response_service_url = 'https://idp-response.example.test/saml/logout'
      settings.certificate = 'ORIGINAL_SP_CERTIFICATE'
      settings.private_key = 'ORIGINAL_SP_PRIVATE_KEY'
      settings.sp_cert_multi = {
        signing: [{ certificate: 'MULTI_SP_CERTIFICATE', private_key: 'MULTI_SP_PRIVATE_KEY' }]
      }
      settings.security[:logout_responses_signed] = true
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.compress_request = false
      settings.compress_response = false
    end
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

  def signed_logout_request_params(relay_state: home_url, **options)
    OneLogin::RubySaml::Logoutrequest.new.create_params(
      incoming_slo_settings(**options),
      'RelayState' => relay_state
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

  def saml_auth_hash_with_private_keys
    private_keys = %w[VERY_SECRET_TEST_PRIVATE_KEY VERY_SECRET_TEST_SP_CERT_MULTI_PRIVATE_KEY]
    settings = OneLogin::RubySaml::Settings.new(
      private_key: private_keys.first,
      sp_cert_multi: {
        signing: [{ certificate: 'PUBLIC_SP_CERTIFICATE', private_key: private_keys.last }]
      }
    )
    response_xml = <<~XML.delete "\n"
      <samlp:Response Destination="https://sp.example.test/auth/saml/callback" InResponseTo="_request-id" ID="_response-id">
        <saml:Issuer>https://idp.example.test/metadata</saml:Issuer>
        <ds:Signature><ds:X509Certificate>IDP_CERTIFICATE_LOG_FIXTURE</ds:X509Certificate></ds:Signature>
        <saml:Assertion>
          <saml:Subject><saml:NameID>_name-id-for-safe-log-test</saml:NameID></saml:Subject>
          <saml:Conditions>
            <saml:AudienceRestriction><saml:Audience>https://sp.example.test</saml:Audience></saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement SessionIndex="_session-index-for-safe-log-test">
            <saml:AuthnContext><saml:AuthnContextClassRef>urn:test:authn-context</saml:AuthnContextClassRef></saml:AuthnContext>
          </saml:AuthnStatement>
        </saml:Assertion>
      </samlp:Response>
    XML
    response = OneLogin::RubySaml::Response.allocate
    response.instance_variable_set :@response, response_xml
    decrypted_document = XMLSecurity::SignedDocument.new(
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">' \
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' \
      'DECRYPTED_ASSERTION_LOG_FIXTURE' \
      '</saml:Assertion></samlp:Response>'
    )
    response.instance_variable_set :@decrypted_document, decrypted_document
    response.settings = settings
    raw_info = OneLogin::RubySaml::Attributes.new(
      'department-for-safe-log-test' => ['Engineering'],
      'email' => ['admin@example.test']
    )
    auth = OmniAuth::AuthHash.new(
      provider: 'saml',
      uid: '_name-id-for-safe-log-test',
      info: {
        email: 'admin@example.test',
        name: 'Redmine Admin',
        first_name: 'Redmine',
        last_name: 'Admin'
      },
      extra: {
        raw_info: raw_info,
        session_index: '_session-index-for-safe-log-test',
        response_object: response
      },
      saml_login: 'admin'
    )

    [auth, response, response_xml, decrypted_document, private_keys]
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
