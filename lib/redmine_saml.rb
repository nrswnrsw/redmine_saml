# frozen_string_literal: true

require_relative 'redmine_saml/slo_context'
require_relative 'redmine_saml/slo_token_store'
require_relative 'redmine_saml/slo_cookie'
require_relative 'redmine_saml/slo_post_signature'
require_relative 'redmine_saml/sudo_context'
require_relative 'redmine_saml/sudo_session'
require_relative 'redmine_saml/sudo_token_store'
require_relative 'redmine_saml/sudo_continuation'
require_relative 'redmine_saml/sudo_reauth'

module RedmineSaml
  VERSION = '1.2.0'

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

    # Optional administrator overrides for the SAML Sudo Mode confirmation
    # prompt. Each one is blank by default, and the view then falls back to the
    # translation of the current locale, so an unconfigured Redmine keeps the
    # prompt it always had in every language.
    def saml_sudo_reauth_title
      setting :saml_sudo_reauth_title
    end

    def saml_sudo_reauth_text
      setting :saml_sudo_reauth_text
    end

    def saml_sudo_reauth_button_label
      setting :saml_sudo_reauth_button_label
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
                   SettingsController
                   ApplicationController]
      loader.add_patch patches

      # Apply patches and helper
      loader.apply!

      SloTokenStore.register_action!

      # SAML Sudo Mode re-authentication is installed on every supported
      # Redmine release and gated at request time by Redmine's own Sudo Mode,
      # exactly as Redmine gates its Sudo Mode controller hooks. While Sudo
      # Mode is off, both entry points below return immediately.
      SudoTokenStore.register_action!
      SudoReauth.install_setup_phase!

      # Load view hooks
      loader.load_view_hooks!
    end
  end
end
