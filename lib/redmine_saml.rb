# frozen_string_literal: true

require_relative 'redmine_saml/slo_context'
require_relative 'redmine_saml/slo_token_store'
require_relative 'redmine_saml/slo_cookie'
require_relative 'redmine_saml/slo_post_signature'
require_relative 'redmine_saml/sudo_context'
require_relative 'redmine_saml/sudo_token_store'
require_relative 'redmine_saml/sudo_reauth'

module RedmineSaml
  VERSION = '1.1.1'

  METADATA_PATH = '/auth/saml/metadata'
  CALLBACK_PATH = '/auth/saml/callback'
  LOGOUT_SERVICE_PATH = '/auth/saml/sls'

  include RedminePluginKit::PluginBase

  class << self
    def enabled?
      setting? :saml_enabled
    end

    def onthefly_creation?
      enabled? && setting?(:onthefly_creation)
    end

    def replace_redmine_login?
      setting? :replace_redmine_login
    end

    def saml_login_label
      setting :saml_login_label
    end

    # These are intentionally explicit singleton-method wrappers.
    # rubocop:disable Rails/Delegate
    def user_attributes_from_saml(omniauth)
      Base.user_attributes_from_saml omniauth
    end

    def configured_saml
      Base.configured_saml
    end

    def on_login_callback
      Base.on_login_callback
    end
    # rubocop:enable Rails/Delegate

    private

    def setup
      # Patches
      patches = %w[User
                   AccountController
                   SettingsController]
      # SAML Sudo Mode re-authentication is a Redmine 7.0+ feature. On older
      # releases the ApplicationController patch is not applied at all, so
      # Sudo Mode keeps its unmodified Redmine behaviour there.
      patches << 'ApplicationController' if SudoReauth.supported?
      loader.add_patch patches

      # Apply patches and helper
      loader.apply!

      SloTokenStore.register_action!

      # Runs after every plugin is loaded, which is the first point where
      # Redmine::VERSION is available, so Redmine 6.0 and 6.1 get neither the
      # Token action nor the OmniAuth setup_phase extension.
      if SudoReauth.supported?
        SudoTokenStore.register_action!
        SudoReauth.install_setup_phase!
      end

      # Load view hooks
      loader.load_view_hooks!
    end
  end
end
