# frozen_string_literal: true

module OmniauthSamlAccountHelper
  SAML_SETTINGS_REDACTED = '[REDACTED]'

  def saml_login_label
    RedmineSaml.saml_login_label.presence || l(:saml_login_label)
  end

  def saml_request_javascript_path
    path = javascript_path 'plugin_assets/redmine_saml/saml_request'
    script_name = request.script_name.to_s.chomp '/'
    path_already_prefixed = path.start_with? "#{script_name}/"
    return path if script_name.blank? || path_already_prefixed

    script_name_root_relative = script_name.start_with? '/'
    script_name_protocol_relative = script_name.start_with? '//'
    path_root_relative = path.start_with? '/'
    path_protocol_relative = path.start_with? '//'
    valid_script_name = script_name_root_relative && !script_name_protocol_relative
    root_relative_path = path_root_relative && !path_protocol_relative
    return path unless valid_script_name && root_relative_path

    "#{script_name}#{path}"
  end

  def saml_settings_for_display(settings)
    sanitize_saml_settings settings
  end

  def saml_url_validate_test(url1, url2)
    url1 == url2 ? image_tag('true.png', title: "#{url1} == #{url2}") : image_tag('false.png', title: "#{url1} != #{url2}")
  end

  private

  def sanitize_saml_settings(value, in_sp_cert_multi: false)
    case value
    when Hash
      value.each_with_object({}) do |(key, nested_value), sanitized|
        key_name = key.to_s
        sanitized[key] = if key_name == 'private_key' || (in_sp_cert_multi && key_name == 'key')
                           SAML_SETTINGS_REDACTED
                         else
                           sanitize_saml_settings nested_value,
                                                  in_sp_cert_multi: in_sp_cert_multi || key_name == 'sp_cert_multi'
                         end
      end
    when Array
      value.map { |nested_value| sanitize_saml_settings nested_value, in_sp_cert_multi: in_sp_cert_multi }
    else
      value
    end
  end
end
