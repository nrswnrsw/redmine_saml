# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SamlSettingsControllerTest < RedmineSaml::ControllerTest
  fixtures :users

  tests SettingsController

  setup do
    @saved_saml_configuration = RedmineSaml.configured_saml.deep_dup
    User.current = nil
    prepare_tests
    @request.session[:user_id] = 1
  end

  teardown do
    RedmineSaml.configured_saml.replace @saved_saml_configuration
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

    should 'redact a legacy SP private key without hiding non-secret SAML settings' do
      configured_saml = RedmineSaml.configured_saml
      configured_saml.delete :sp_cert_multi
      configured_saml.delete :idp_cert_fingerprint
      configured_saml[:private_key] = 'VERY_SECRET_SP_PRIVATE_KEY'
      configured_saml[:certificate] = 'PUBLIC_SP_CERTIFICATE'
      configured_saml[:idp_sso_service_url] = 'https://idp.example.test/saml/sso'
      configured_saml[:idp_slo_service_url] = 'https://idp.example.test/saml/slo'
      configured_saml[:idp_cert] = 'PUBLIC_IDP_CERTIFICATE'
      configured_saml[:attribute_mapping] = { login: 'extra|raw_info|username',
                                              mail: 'extra|raw_info|mail',
                                              firstname: 'extra|raw_info|firstname',
                                              lastname: 'extra|raw_info|lastname' }
      original_configuration = configured_saml.deep_dup

      get :plugin, params: { id: 'redmine_saml', tab: 'info' }

      assert_response :success
      assert_select 'td.name', text: 'private_key'
      assert_includes response.body, OmniauthSamlAccountHelper::SAML_SETTINGS_REDACTED
      assert_not_includes response.body, 'VERY_SECRET_SP_PRIVATE_KEY'
      assert_includes response.body, 'PUBLIC_SP_CERTIFICATE'
      assert_includes response.body, 'https://idp.example.test/saml/sso'
      assert_includes response.body, 'https://idp.example.test/saml/slo'
      assert_includes response.body, 'PUBLIC_IDP_CERTIFICATE'
      assert_includes response.body, 'extra|raw_info|username'
      assert_same configured_saml, RedmineSaml.configured_saml
      assert_equal original_configuration, RedmineSaml.configured_saml
      assert_equal 'VERY_SECRET_SP_PRIVATE_KEY', RedmineSaml.configured_saml[:private_key]
    end

    should 'redact signing and encryption keys in legacy sp_cert_multi settings' do
      configured_saml = RedmineSaml.configured_saml
      configured_saml.delete :private_key
      configured_saml.delete :certificate
      configured_saml[:sp_cert_multi] = {
        signing: [
          {
            certificate: 'PUBLIC_SIGNING_CERTIFICATE',
            private_key: 'VERY_SECRET_SIGNING_PRIVATE_KEY'
          }
        ],
        encryption: [
          {
            certificate: 'PUBLIC_ENCRYPTION_CERTIFICATE',
            private_key: 'VERY_SECRET_ENCRYPTION_PRIVATE_KEY'
          },
          {
            cert: 'PUBLIC_ALIAS_CERTIFICATE',
            key: 'VERY_SECRET_ALIAS_PRIVATE_KEY'
          }
        ]
      }
      original_configuration = configured_saml.deep_dup

      get :plugin, params: { id: 'redmine_saml', tab: 'info' }

      assert_response :success
      assert_includes response.body, 'private_key'
      assert_includes response.body, OmniauthSamlAccountHelper::SAML_SETTINGS_REDACTED
      assert_not_includes response.body, 'VERY_SECRET_SIGNING_PRIVATE_KEY'
      assert_not_includes response.body, 'VERY_SECRET_ENCRYPTION_PRIVATE_KEY'
      assert_not_includes response.body, 'VERY_SECRET_ALIAS_PRIVATE_KEY'
      assert_includes response.body, 'PUBLIC_SIGNING_CERTIFICATE'
      assert_includes response.body, 'PUBLIC_ENCRYPTION_CERTIFICATE'
      assert_includes response.body, 'PUBLIC_ALIAS_CERTIFICATE'
      assert_same configured_saml, RedmineSaml.configured_saml
      assert_equal original_configuration, RedmineSaml.configured_saml
      assert_equal 'VERY_SECRET_SIGNING_PRIVATE_KEY',
                   RedmineSaml.configured_saml.dig(:sp_cert_multi, :signing, 0, :private_key)
      assert_equal 'VERY_SECRET_ENCRYPTION_PRIVATE_KEY',
                   RedmineSaml.configured_saml.dig(:sp_cert_multi, :encryption, 0, :private_key)
      assert_equal 'VERY_SECRET_ALIAS_PRIVATE_KEY', RedmineSaml.configured_saml.dig(:sp_cert_multi, :encryption, 1, :key)
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
