# frozen_string_literal: true

require_dependency 'application_controller'

module RedmineSaml
  module Patches
    module ApplicationControllerPatch
      extend ActiveSupport::Concern

      included do
        # The Sudo Mode prompt is rendered from whatever controller asked for
        # confirmation, so the display texts of that prompt are resolved by a
        # helper of its own here. The login side keeps its own helper.
        helper :omniauth_saml_sudo

        prepend InstanceOverwriteMethods
      end

      module InstanceOverwriteMethods
        # Redmine::SudoMode::Controller#render_sudo_form asks for the local
        # Redmine password. SAML-only users do not have one, so a session that
        # was created by SAML is offered SAML re-authentication instead. Every
        # other session, including a local login on a SAML enabled Redmine,
        # keeps the standard Redmine prompt.
        def render_sudo_form(param_names)
          return super unless RedmineSaml::SudoReauth.available? session: session

          @sudo_form ||= ::Redmine::SudoMode::Form.new
          @sudo_form.original_fields = params.slice(*param_names)
          @saml_sudo_return_url = saml_sudo_return_path
          # a simple 'render "saml/sudo_mode/new"' works when used directly
          # inside an action, but not when called from a before_action
          no_store
          respond_to do |format|
            format.html { render 'saml/sudo_mode/new' }
            format.js   { render 'saml/sudo_mode/new' }
          end
        end

        private

        # The original request is not replayed after the IdP round trip, so the
        # user is returned to a safe GET URL and repeats the action there. The
        # value is validated here and again after the callback, so neither the
        # form nor the SAML transaction can introduce an open redirect.
        def saml_sudo_return_path
          validate_back_url(back_url.to_s) || home_path
        end
      end
    end
  end
end
