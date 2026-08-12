# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class AccountSAMLTest < Redmine::IntegrationTest
  OMNIAUTH_SLO_PATH_VARIANTS = %w[
    /auth/saml/slo
    /auth/saml/slo/
    /AUTH/SAML/SLO
    /auth/SAML/slo
  ].freeze
  OMNIAUTH_SPSLO_PATH_VARIANTS = %w[
    /auth/saml/spslo
    /auth/saml/spslo/
    /AUTH/SAML/SPSLO
    /auth/SAML/spslo
  ].freeze

  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  include RedmineSaml::TestHelper

  setup do
    prepare_tests
  end

  context 'SAML authentication when disabled' do
    setup do
      Setting.default_language = 'en'
      change_saml_settings saml_enabled: 0,
                           onthefly_creation: 0

      OmniAuth.config.test_mode = true
    end

    should 'reject the SAML request phase before OmniAuth starts authentication' do
      post '/auth/saml'

      assert_redirected_to '/login'
      follow_redirect!
      assert_equal User.anonymous, User.current
    end

    should 'reject an IdP-initiated callback for an existing user' do
      OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }

      post RedmineSaml::CALLBACK_PATH

      assert_redirected_to '/login'
      assert_nil session[:user_id]
      assert_not session[:logged_in_with_saml]
      follow_redirect!
      assert_equal User.anonymous, User.current
    end

    should 'normalize SAML request and callback paths before the disabled gate' do
      with_omniauth_production_mode do
        %w[/auth/saml/ /AUTH/SAML /auth/SAML /auth/saml/callback/ /AUTH/SAML/CALLBACK /auth/SAML/callback].each do |path|
          post path

          assert_redirected_to '/login', path
          assert_nil session[:user_id], path
          assert_not session[:logged_in_with_saml], path
        end
      end
    end

    should 'block every unsupported OmniAuth SLO path variant while SAML is disabled' do
      with_omniauth_production_mode do
        (OMNIAUTH_SLO_PATH_VARIANTS + OMNIAUTH_SPSLO_PATH_VARIANTS).each do |path|
          get path

          assert_response :not_found, path
          assert_empty response.body, path
          assert_nil session[:user_id], path
        end
      end
    end
  end

  context 'GET /auth/:provider/callback' do
    context 'OmniAuth SAML strategy' do
      setup do
        Setting.default_language = 'en'
        change_saml_settings saml_enabled: 1,
                             onthefly_creation: 0

        OmniAuth.config.test_mode = true
      end

      should 'authorize login if user exists with this login' do
        OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }

        get RedmineSaml::CALLBACK_PATH
        assert_redirected_to '/my/page'

        get '/my/page'
        assert_select 'div.flyout-menu__avatar a.user.active', text: 'admin'
      end

      should 'authorize login if user exists with this mail' do
        OmniAuth.config.mock_auth[:saml] = { 'mail' => 'admin@somenet.foo' }

        get RedmineSaml::CALLBACK_PATH
        assert_redirected_to '/my/page'

        get '/my/page'
        assert_select 'div.flyout-menu__avatar a.user.active', text: 'admin'
      end

      should 'update last_login_on field' do
        user = users :users_001
        user.update_attribute :last_login_on, 6.hours.ago
        OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }

        get RedmineSaml::CALLBACK_PATH
        assert_redirected_to '/my/page'
        user.reload
        assert Time.zone.now - user.last_login_on < 30.seconds
      end

      should "refuse login if user doesn't exist" do
        OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'johndoe' }
        get RedmineSaml::CALLBACK_PATH
        assert_redirected_to '/login'
        follow_redirect!
        assert_equal User.anonymous, User.current
        assert_select 'div.flash.error', text: /Invalid user or password/
      end

      should "create user if doesn't exist when on thefly_creation is set" do
        change_saml_settings onthefly_creation: 1

        login_name = 'johndoe'
        assert_difference 'User.count' do
          OmniAuth.config.mock_auth[:saml] = { 'saml_login' => login_name,
                                               'first_name' => 'first name',
                                               'last_name' => 'last name',
                                               'mail' => 'mail@example.com' }
          get RedmineSaml::CALLBACK_PATH

          assert_redirected_to '/my/page'
          follow_redirect!
        end

        assert User.exists? login: login_name
      end
    end
  end

  context 'unused OmniAuth SLO endpoints' do
    setup do
      Setting.default_language = 'en'
      change_saml_settings saml_enabled: 1,
                           onthefly_creation: 0
      OmniAuth.config.test_mode = true
      OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }

      login_with_mock_saml_session users(:users_001).mail
      assert_redirected_to '/my/page'
      assert_active_saml_session
    end

    should 'not expose the unverified OmniAuth SLO handler' do
      post '/auth/saml/slo', params: { SAMLRequest: 'invalid' }

      assert_response :not_found
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
    end

    should 'not allow a GET to start the OmniAuth SP logout handler' do
      get '/auth/saml/spslo'

      assert_response :not_found
      assert_equal users(:users_001).id, session[:user_id]
      assert session[:logged_in_with_saml]
    end

    should 'block every OmniAuth SLO path variant before the production handler can clear the session' do
      request_params = unsigned_logout_request_params
      assert_valid_unsigned_logout_request request_params

      with_omniauth_production_mode do
        OMNIAUTH_SLO_PATH_VARIANTS.each do |path|
          get path, params: request_params

          assert_response :not_found, path
          assert_empty response.body, path
          assert_active_saml_session path
        end
      end
    end

    should 'block every OmniAuth SP logout path variant in production mode' do
      with_omniauth_production_mode do
        OMNIAUTH_SPSLO_PATH_VARIANTS.each do |path|
          get path

          assert_response :not_found, path
          assert_empty response.body, path
          assert_active_saml_session path
        end
      end
    end

    should 'leave the custom hardened SLS endpoint available in production mode' do
      with_omniauth_production_mode do
        get RedmineSaml::LOGOUT_SERVICE_PATH
      end

      assert_response :bad_request
      assert_active_saml_session
    end

    should 'not treat similar SAML paths as unsupported OmniAuth endpoints' do
      downstream = ->(_env) { [204, {}, ['downstream']] }
      gate = RedmineSaml::AuthenticationGate.new downstream

      %w[/auth/saml/slo-extra /auth/saml/spslo-extra /auth/saml/sls].each do |path|
        status, _headers, body = gate.call 'PATH_INFO' => path

        assert_equal 204, status, path
        assert_equal ['downstream'], body, path
      end
    end
  end

  private

  def login_with_mock_saml_session(saml_uid)
    original_callback_phase = OmniAuth.config.before_callback_phase
    OmniAuth.config.before_callback_phase = proc do |env|
      original_callback_phase&.call env
      env['rack.session']['saml_uid'] = saml_uid
      env['rack.session']['saml_session_index'] = 'integration-test-session-index'
    end

    get RedmineSaml::CALLBACK_PATH
  ensure
    OmniAuth.config.before_callback_phase = original_callback_phase
  end

  def with_omniauth_production_mode
    original_test_mode = OmniAuth.config.test_mode
    OmniAuth.config.test_mode = false
    yield
  ensure
    OmniAuth.config.test_mode = original_test_mode
  end

  def unsigned_logout_request_params
    settings = OneLogin::RubySaml::Settings.new
    settings.idp_slo_service_url = RedmineSaml.configured_saml[:single_logout_service_url]
    settings.sp_entity_id = 'https://attacker.example.test/metadata'
    settings.name_identifier_value = users(:users_001).mail
    settings.name_identifier_format = RedmineSaml.configured_saml[:name_identifier_format]
    settings.security[:logout_requests_signed] = false

    OneLogin::RubySaml::Logoutrequest.new.create_params settings
  end

  def assert_valid_unsigned_logout_request(request_params)
    assert_nil request_params['Signature']
    settings = OneLogin::RubySaml::Settings.new RedmineSaml.configured_saml
    logout_request = OneLogin::RubySaml::SloLogoutrequest.new(
      request_params['SAMLRequest'],
      settings: settings,
      get_params: request_params
    )

    assert logout_request.is_valid?, logout_request.errors.join(', ')
    assert_equal users(:users_001).mail, logout_request.name_id
  end

  def assert_active_saml_session(message = nil)
    assert_equal users(:users_001).id, session[:user_id], message
    assert session[:logged_in_with_saml], message
    assert_equal users(:users_001).mail, session['saml_uid'], message
    assert_equal 'integration-test-session-index', session['saml_session_index'], message
  end
end
