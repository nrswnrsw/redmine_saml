# frozen_string_literal: true

require File.expand_path "#{File.dirname __FILE__}/../../../test/test_helper"
require File.expand_path "#{File.dirname __FILE__}/support/saml_response_builder"

module RedmineSaml
  module TestHelper
    def self.included(base)
      base.teardown :restore_saml_settings
    end

    def attribute_mapping_mock
      { login: 'saml_login',
        firstname: 'first_name',
        lastname: 'last_name',
        mail: 'mail',
        admin: 'admin' }
    end

    def prepare_tests
      change_saml_settings saml_enabled: 1
      RedmineSaml.configured_saml[:attribute_mapping] = attribute_mapping_mock
    end

    def change_saml_settings(settings)
      @saved_settings ||= Setting.plugin_redmine_saml.dup
      new_settings = Setting.plugin_redmine_saml.dup
      settings.each do |key, value|
        new_settings[key] = value
      end
      Setting.plugin_redmine_saml = new_settings
    end

    def restore_saml_settings
      return unless instance_variable_defined? :@saved_settings

      Setting.plugin_redmine_saml = @saved_settings
      remove_instance_variable :@saved_settings
    end

    # The initializer SAML configuration is a different thing from the Redmine
    # plugin settings handled by change_saml_settings / restore_saml_settings,
    # so tests that change it save and restore it from their own setup/teardown.
    def save_saml_configuration
      @saved_saml_configuration = RedmineSaml.configured_saml.deep_dup
    end

    def restore_saml_configuration
      RedmineSaml.configured_saml.replace @saved_saml_configuration
    end

    # Runs the block against real, signed SAML Responses instead of the
    # OmniAuth test mode, so the whole callback phase of omniauth-saml and
    # ruby-saml is exercised.
    def with_real_saml_responses
      original_test_mode = OmniAuth.config.test_mode
      save_saml_configuration
      OmniAuth.config.test_mode = false
      RedmineSaml.configured_saml.delete :idp_cert_fingerprint
      RedmineSaml.configured_saml.merge! RedmineSaml::SamlResponseBuilder.settings_overrides
      yield
    ensure
      OmniAuth.config.test_mode = original_test_mode
      restore_saml_configuration
    end

    def with_forgery_protection
      original_forgery_protection = ActionController::Base.allow_forgery_protection
      ActionController::Base.allow_forgery_protection = true
      yield
    ensure
      ActionController::Base.allow_forgery_protection = original_forgery_protection
    end
  end

  class ControllerTest < Redmine::ControllerTest
    include RedmineSaml::TestHelper
  end

  class TestCase < ActiveSupport::TestCase
    include RedmineSaml::TestHelper
  end
end
