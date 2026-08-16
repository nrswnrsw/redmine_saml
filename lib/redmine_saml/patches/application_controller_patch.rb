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
            format.html do
              prepare_saml_sudo_continuation
              render 'saml/sudo_mode/new'
            end
            # The modal is reached from a remote form, which this confirmation
            # cannot resume: the tab navigates away to the IdP, so the page that
            # would receive the XHR response no longer exists when it returns.
            # It therefore keeps the 1.2.0 behaviour and offers no continuation.
            format.js { render 'saml/sudo_mode/new' }
          end
        end

        private

        # Seals the fields Redmine::SudoMode selected for this request into one
        # opaque string for the browser to keep across the IdP round trip, and
        # sends the transaction back to the resume page instead of straight to
        # the back URL.
        #
        # Nothing is stored server side and the Sudo transaction itself is
        # untouched. Losing a draft is a far better outcome than failing the
        # confirmation, so anything unexpected here simply falls back to the
        # 1.2.0 behaviour of returning without the input.
        def prepare_saml_sudo_continuation
          return unless RedmineSaml::SudoContinuation.resumable_method? request.request_method

          fields = RedmineSaml::SudoContinuation.serializable_fields @sudo_form.original_fields
          return if fields.blank?

          continuation = RedmineSaml::SudoContinuation.dump user_id: User.current.id,
                                                            session_secret: saml_sudo_continuation_secret,
                                                            request_method: request.request_method,
                                                            path: request.path,
                                                            fields: fields
          return if continuation.blank?

          @saml_sudo_continuation = continuation
          @saml_sudo_continuation_key = RedmineSaml::SudoContinuation.generate_key
          @saml_sudo_return_url = saml_sudo_resume_path key: @saml_sudo_continuation_key,
                                                        back_url: @saml_sudo_return_url
        rescue StandardError => e
          logger.warn "SAML sudo continuation skipped: #{e.class}"
          @saml_sudo_continuation = nil
          @saml_sudo_continuation_key = nil
        end

        # Per login session secret a continuation is bound to. Derived from the
        # Redmine session token, so it is the same for every tab of one login
        # session even when they ask for it at the very same moment, differs
        # between login sessions, and is never stored anywhere.
        def saml_sudo_continuation_secret
          RedmineSaml::SudoContinuation.session_secret session
        end

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
