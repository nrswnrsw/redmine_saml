# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SamlSettingsControllerTest < RedmineSaml::ControllerTest
  fixtures :users

  tests SettingsController

  setup do
    User.current = nil
    prepare_tests
    @request.session[:user_id] = 1
  end

  context 'GET plugin settings' do
    should 'render SAML settings with Redmine form helpers' do
      change_saml_settings saml_enabled: 1,
                           saml_login_label: 'Company SSO',
                           replace_redmine_login: 0,
                           onthefly_creation: 1

      get :plugin, params: { id: 'redmine_saml' }

      assert_response :success
      assert_select 'input[type=?][name=?][value=?]', 'hidden', 'settings[saml_enabled]', '0'
      assert_select 'input[type=?][name=?][value=?][checked=?]',
                    'checkbox', 'settings[saml_enabled]', '1', 'checked'
      assert_select 'input[type=?][name=?][value=?]',
                    'text', 'settings[saml_login_label]', 'Company SSO'
      assert_select 'input[type=?][name=?][value=?]', 'hidden', 'settings[replace_redmine_login]', '0'
      assert_select 'input[type=?][name=?]', 'checkbox', 'settings[replace_redmine_login]' do |elements|
        assert_nil elements.first['checked']
      end
      assert_select 'input[type=?][name=?][value=?]', 'hidden', 'settings[onthefly_creation]', '0'
      assert_select 'input[type=?][name=?][value=?][checked=?]',
                    'checkbox', 'settings[onthefly_creation]', '1', 'checked'
    end
  end

  context 'POST plugin settings' do
    should 'save SAML settings' do
      post :plugin,
           params: {
             id: 'redmine_saml',
             settings: {
               saml_enabled: '0',
               saml_login_label: 'Updated SSO',
               replace_redmine_login: '1',
               onthefly_creation: '0'
             }
           }

      assert_redirected_to plugin_settings_path(Redmine::Plugin.find('redmine_saml'))
      assert_equal '0', Setting.plugin_redmine_saml[:saml_enabled]
      assert_equal 'Updated SSO', Setting.plugin_redmine_saml[:saml_login_label]
      assert_equal '1', Setting.plugin_redmine_saml[:replace_redmine_login]
      assert_equal '0', Setting.plugin_redmine_saml[:onthefly_creation]
    end
  end
end
