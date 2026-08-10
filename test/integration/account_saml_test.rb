# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class AccountSAMLTest < Redmine::IntegrationTest
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

      get RedmineSaml::CALLBACK_PATH
      assert_redirected_to '/my/page'
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
  end
end
