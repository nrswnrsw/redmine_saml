# frozen_string_literal: true

loader = RedminePluginKit::Loader.new plugin_id: 'redmine_saml'

Redmine::Plugin.register :redmine_saml do
  name 'Redmine SAML'
  description 'This plugin adds Omniauth SAML support to Redmine.'
  author 'AlphaNodes GmbH'
  author_url 'https://alphanodes.com/'
  url 'https://github.com/alphanodes/redmine_saml'
  version RedmineSaml::VERSION
  requires_redmine version_or_higher: '6.0'

  settings default: loader.default_settings,
           partial: 'saml/settings/saml'
end

RedminePluginKit::Loader.persisting { loader.load_model_hooks! }
