# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SAMLTest < RedmineSaml::TestCase
  setup do
    prepare_tests
  end

  context '#enabled?' do
    should 'return enabled? if setting is set' do
      change_saml_settings saml_enabled: 0
      assert_not RedmineSaml.enabled?
    end
  end

  context '#onthefly_creation?' do
    should 'return onthefly_creation false if setting is set and plugin is disabled' do
      change_saml_settings saml_enabled: 0,
                           onthefly_creation: 1
      assert_not RedmineSaml.onthefly_creation?
    end

    should 'return onthefly_creation if setting is set and plugin is enabled' do
      change_saml_settings saml_enabled: 1,
                           onthefly_creation: 1
      assert RedmineSaml.onthefly_creation?
    end
  end

  context '#saml_login_label' do
    should 'return saml_login_label if setting is set' do
      val = '1234'
      change_saml_settings saml_login_label: val
      assert_equal val, RedmineSaml.saml_login_label
    end
  end

  context 'legacy attribute mapping compatibility' do
    should 'require only login mail firstname and lastname' do
      assert_equal %i[login firstname lastname mail],
                   RedmineSaml::Base.send(:required_attribute_mapping)
    end

    should 'reject an existing alphanodes initializer missing any required mapping' do
      mapping = { login: 'saml_login',
                  mail: 'mail',
                  firstname: 'first_name',
                  lastname: 'last_name' }

      mapping.each_key do |required_key|
        error = assert_raises RuntimeError do
          configure_legacy_attribute_mapping mapping.except(required_key)
        end
        assert_equal "RedmineSaml.configure requires saml.attribute_mapping[#{required_key}] to be set",
                     error.message
      end
    end

    should 'configure without an admin mapping for existing alphanodes initializers' do
      mapping = { login: 'saml_login',
                  mail: 'mail',
                  firstname: 'first_name',
                  lastname: 'last_name' }

      assert_legacy_attribute_mapping_configures mapping
    end

    should 'configure with an unused admin mapping for existing alphanodes initializers' do
      mapping = attribute_mapping_mock

      assert_legacy_attribute_mapping_configures mapping
    end
  end

  private

  def assert_legacy_attribute_mapping_configures(mapping)
    configured_mapping = nil
    RedmineSaml::Base.expects(:configure_omniauth_saml_middleware).once

    assert_nothing_raised do
      configured_mapping = configure_legacy_attribute_mapping mapping
    end
    assert_equal mapping.with_indifferent_access, configured_mapping
  end

  def configure_legacy_attribute_mapping(mapping)
    original_saml = RedmineSaml::Base.saml
    original_validation = RedmineSaml::Base.instance_variable_get :@validated_configuration
    saml = original_saml.deep_dup
    saml[:attribute_mapping] = mapping

    RedmineSaml::Base.configure { |config| config.saml = saml }
    RedmineSaml.configured_saml[:attribute_mapping].deep_dup
  ensure
    RedmineSaml::Base.instance_variable_set :@saml, original_saml
    RedmineSaml::Base.instance_variable_set :@validated_configuration, original_validation
  end
end
