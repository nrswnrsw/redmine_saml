# frozen_string_literal: true

require_dependency 'account_controller'

require_relative '../redirect_binding'

module RedmineSaml
  module Patches
    module AccountControllerPatch
      SAML_REDIRECT_QUERY_PARAMETERS = RedmineSaml::RedirectBinding::SAML_REDIRECT_QUERY_PARAMETERS
      SAML_REDIRECT_RAW_PARAMETERS = RedmineSaml::RedirectBinding::SAML_REDIRECT_RAW_PARAMETERS

      extend ActiveSupport::Concern

      included do
        prepend InstanceOverwriteMethods

        helper :omniauth_saml_account

        before_action :require_saml_enabled,
                      only: %i[login_with_saml_redirect login_with_saml_callback redirect_after_saml_logout]
        before_action :verify_authenticity_token,
                      except: %i[login_with_saml_callback redirect_after_saml_logout]
        before_action :require_saml_sudo_reauth_available, only: %i[saml_sudo_reauth saml_sudo_resume]
      end

      module InstanceOverwriteMethods
        def login
          if RedmineSaml.enabled? && RedmineSaml.replace_redmine_login?
            redirect_to login_with_saml_redirect_path(provider: 'saml', origin: back_url)
          else
            result = super
            clear_slo_cookies if saml_post_binding_request? && User.current.logged? && !session[:logged_in_with_saml]
            result
          end
        end

        def login_with_saml_redirect
          return head :method_not_allowed unless request.request_method == 'GET'

          # Starting a normal SAML login supersedes any pending Sudo
          # transaction, so the next callback cannot be mistaken for one.
          cancel_saml_sudo_reauth
          @saml_origin = validate_back_url params[:origin].to_s
          no_store
          render 'saml/login_with_saml_redirect'
        end

        # Starts a SAML transaction that only re-establishes Sudo Mode for the
        # user who is already signed in. It never replaces the Redmine session.
        def saml_sudo_reauth
          return head :method_not_allowed unless request.request_method == 'POST'

          requested_return_url = validate_back_url(params[:back_url].to_s) || home_path
          if active_saml_sudo_reauth_transaction
            # One Redmine login session has one SAML Sudo transaction. A later
            # tab keeps its own continuation in sessionStorage and returns to
            # its own resume page, while the first tab completes the shared
            # confirmation. Nothing about the first transaction is touched.
            logger.info 'Kept the pending SAML sudo re-authentication for a later tab'
            return redirect_to requested_return_url
          end

          cancel_saml_sudo_reauth
          # The AuthnRequest is built from the configured SAML settings, used
          # unchanged, so the plugin never adds or removes an authentication
          # condition such as ForceAuthn or IsPassive on its own. With a static
          # initializer that makes the Sudo AuthnRequest carry the same
          # authentication conditions as a normal login. Settings a deployment
          # changes per request through an OmniAuth :setup endpoint do not
          # reach this point, which the README documents.
          settings = omniauth_saml_settings
          authn_request = OneLogin::RubySaml::Authrequest.new
          nonce = RedmineSaml::SudoReauth.generate_nonce
          token = RedmineSaml::SudoTokenStore.create_transaction User.current
          # Registered before the AuthnRequest can reach the IdP, so every
          # Response the IdP could produce for it is already recognisable as a
          # Sudo one. The entry outlives this transaction on purpose.
          RedmineSaml::SudoTokenStore.register_request User.current, authn_request.uuid
          context = RedmineSaml::SudoContext.build(
            user_id: User.current.id,
            request_id: authn_request.uuid,
            nonce: nonce,
            token: token,
            return_url: requested_return_url,
            saml_uid: session['saml_uid'],
            saml_session_index: session['saml_session_index'],
            settings: settings
          )
          redirect_url = authn_request.create OneLogin::RubySaml::Settings.new(settings),
                                              RelayState: RedmineSaml::SudoReauth.relay_state(nonce)
          logger.info "New SAML sudo re-authentication for userid '#{User.current.login}' " \
                      "requestid '#{authn_request.uuid}'"
          session[RedmineSaml::SudoReauth::SESSION_KEY] = context
          redirect_to redirect_url, allow_other_host: true
        rescue StandardError => e
          token&.destroy
          session.delete RedmineSaml::SudoReauth::SESSION_KEY
          logger.warn "SAML sudo re-authentication could not be started: #{e.class}"
          redirect_to home_path
        end

        # Offers the input of the request that triggered a Sudo confirmation
        # back to the user after the IdP round trip.
        #
        # This action never changes anything and is never a decision about
        # whether the original request may run. It reads the continuation the
        # browser kept, in this browser tab only, and renders the input back as
        # an ordinary Redmine form. Submitting that form is a separate, explicit
        # user action which produces a normal Redmine request: it carries a
        # fresh CSRF token and passes through Redmine's own Sudo Mode check
        # again, so a successful SAML callback is on its own never a reason for
        # anything to be changed.
        def saml_sudo_resume
          return head :method_not_allowed unless %w[GET POST].include? request.request_method

          @saml_sudo_back_url = validate_back_url(params[:back_url].to_s) || home_path
          @saml_sudo_continuation_key = saml_sudo_continuation_key
          no_store
          return render 'saml/sudo_mode/resume' if request.request_method == 'GET'

          continuation = RedmineSaml::SudoContinuation.load params[:continuation],
                                                            user_id: User.current.id,
                                                            session_secret: saml_sudo_continuation_secret
          return render_saml_sudo_resume_unavailable if continuation.blank?

          @saml_sudo_continuation_method = continuation['request_method']
          @saml_sudo_continuation_path = continuation['path']
          @saml_sudo_continuation_fields = ActionController::Parameters.new continuation['fields']
          # Read only: what the resumed request is allowed to do is decided by
          # Redmine's own Sudo Mode when that request arrives, not here.
          @saml_sudo_confirmed = sudo_timestamp_valid?
          @saml_sudo_transaction_pending = active_saml_sudo_reauth_transaction.present?
          render 'saml/sudo_mode/continue'
        end

        def login_with_saml_callback
          return handle_saml_sudo_reauth_callback if saml_sudo_reauth_callback?

          auth = request.env['omniauth.auth']
          Rails.logger.info "login_with_saml_callback: #{RedmineSaml::Base.auth_hash_for_logging auth}"
          user = User.find_or_create_from_omniauth auth

          # taken from original AccountController
          if user.blank?
            logger.warn "Failed login for '#{auth[:uid]}' from #{request.remote_ip} at #{Time.now.utc}"
            error = l :notice_account_invalid_credentials
            if RedmineSaml.enabled?
              link = self.class.helpers.link_to l(:text_logout_from_saml),
                                                saml_logout_url(home_url),
                                                target: '_blank',
                                                rel: 'noopener'
              error << ". #{l :text_full_logout_proposal, value: link}"
            end
            if RedmineSaml.replace_redmine_login?
              render_error message: error.html_safe, status: 403 # rubocop:disable Rails/OutputSafety
              false
            else
              flash[:error] = error
              redirect_to signin_url
            end
          elsif !user.active?
            handle_saml_inactive_user user
          else
            user.update_last_login_on!
            params[:back_url] = request.env['omniauth.origin'] if request.env['omniauth.origin'].present?
            saml_uid = session['saml_uid']
            saml_session_index = session['saml_session_index']
            handle_active_user user

            # Cannot be set earlier because handle_active_user() calls
            # successful_authentication(), which resets the session.
            session[:logged_in_with_saml] = true
            session['saml_uid'] = saml_uid if saml_uid.present?
            session['saml_session_index'] = saml_session_index if saml_session_index.present?
            issue_active_slo_context
          end
        end

        def login_with_saml_failure
          error = "error_saml_#{params[:message] || 'unknown'}"
          Rails.logger.warn "login_with_saml_failure: #{error}"
          # OmniAuth rejected the callback before the callback action ran. The
          # RelayState is not forwarded to the OmniAuth failure endpoint, so a
          # Sudo transaction is recognised from the stable failure message of
          # the Sudo setup_phase extension or from a pending transaction in the
          # session.
          return reject_saml_sudo_reauth 'SAML callback was rejected' if saml_sudo_reauth_failure?

          if RedmineSaml.replace_redmine_login?
            render_error message: error.to_sym, status: 500
            false
          else
            flash[:error] = l error.to_sym
            redirect_to signin_url
          end
        end

        def logout
          if RedmineSaml.enabled? && session[:logged_in_with_saml] && saml_post_binding_request?
            sp_logout_request
          else
            result = super
            clear_slo_cookies if saml_post_binding_request?
            result
          end
        end

        # Method to handle IdP initiated logouts
        def idp_logout_request
          validation_complete = false
          active_session = active_saml_logout_session?
          context_available = active_session || saml_post_binding_request?
          return reject_saml_logout 'no active SAML session' unless context_available
          return reject_idp_logout_request 'missing SAML signature' unless valid_saml_signature_parameters?

          settings = OneLogin::RubySaml::Settings.new omniauth_saml_settings
          return reject_idp_logout_request 'SAML message is too large' unless valid_saml_message_size? params[:SAMLRequest], settings

          options = { settings: settings }
          if saml_redirect_binding_request?
            query_options = RedmineSaml::RedirectBinding.query_options request
            return reject_idp_logout_request 'duplicate SAML query parameter' if query_options.blank?

            options.merge! query_options
          end
          logout_request = OneLogin::RubySaml::SloLogoutrequest.new params[:SAMLRequest], options

          valid = logout_request.is_valid? &&
                  valid_post_saml_signature?(logout_request.document, settings) &&
                  valid_saml_message_context?(logout_request, settings)
          return reject_idp_logout_request 'invalid LogoutRequest' unless valid

          fallback_context = nil
          fallback_session_token = nil
          if active_session
            valid = valid_saml_name_id?(logout_request.name_id) &&
                    valid_saml_session_index?(logout_request.session_indexes)
          else
            return reject_idp_logout_request 'non-SAML session is active' if User.current.logged?

            fallback_context = active_slo_context
            valid = fallback_context.present? &&
                    RedmineSaml::SloContext.matching_name_id?(fallback_context, logout_request.name_id) &&
                    RedmineSaml::SloContext.matching_session_indexes?(fallback_context, logout_request.session_indexes)
            fallback_session_token = RedmineSaml::SloTokenStore.valid_session(fallback_context) if valid
            valid &&= fallback_session_token.present?
          end
          return reject_idp_logout_request 'invalid SAML logout context' unless valid

          validation_complete = true
          logger.info "IdP initiated Logout for #{logout_request.name_id}"

          # Generate a response to the IdP.
          logout_request_id = logout_request.id
          logout_response_settings = saml_logout_response_settings settings
          logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create logout_response_settings,
                                                                             logout_request_id,
                                                                             nil,
                                                                             RelayState: params[:RelayState]

          # Actually log out this session only after validation and response generation succeed.
          if active_session
            redirect_to logout_response, allow_other_host: true
            saml_logout_user
            clear_redmine_autologin_cookie
          else
            session_consumed = RedmineSaml::SloTokenStore.consume_session(
              fallback_context,
              fallback_session_token
            )
            return reject_saml_logout 'stale SAML session context' unless session_consumed

            reset_session
            clear_redmine_session_cookie
            clear_redmine_autologin_cookie
            clear_slo_cookies
            redirect_to logout_response, allow_other_host: true
          end
        rescue StandardError => e
          reason = "LogoutRequest validation raised #{e.class}"
          if validation_complete
            reject_saml_logout reason
          else
            reject_idp_logout_request reason
          end
        end

        # After sending an SP initiated LogoutRequest to the IdP, accept and verify
        # the LogoutResponse, then finish the already-local logout transaction.
        def process_logout_response
          validation_complete = false
          context_resolution = resolve_saml_logout_response_context
          return reject_saml_logout context_resolution[:error] if context_resolution[:error]

          transaction_id = context_resolution[:transaction_id]
          return reject_logout_response 'missing SAML transaction ID' if transaction_id.blank?
          return reject_logout_response 'missing SAML signature' unless valid_saml_signature_parameters?

          settings = OneLogin::RubySaml::Settings.new omniauth_saml_settings
          return reject_logout_response 'SAML message is too large' unless valid_saml_message_size? params[:SAMLResponse], settings

          options = { matches_request_id: transaction_id }
          if saml_redirect_binding_request?
            query_options = RedmineSaml::RedirectBinding.query_options request
            return reject_logout_response 'duplicate SAML query parameter' if query_options.blank?

            options.merge! query_options
          end

          logout_response = OneLogin::RubySaml::Logoutresponse.new(
            params[:SAMLResponse],
            settings,
            options
          )

          logger.info "LogoutResponse is: #{logout_response}"

          # Validate the SAML Logout Response
          valid = logout_response.validate &&
                  valid_post_saml_signature?(logout_response.document, settings) &&
                  valid_saml_message_context?(logout_response, settings)
          return reject_logout_response 'invalid LogoutResponse' unless valid

          context = context_resolution[:context]
          if context_resolution[:fallback]
            transaction_consumed = RedmineSaml::SloTokenStore.consume_transaction context
            return reject_logout_response 'stale SAML logout transaction' unless transaction_consumed
          else
            RedmineSaml::SloTokenStore.cleanup_transaction context_resolution[:cleanup_context]
          end

          validation_complete = true
          active_session = context_resolution[:active_session]
          logout_login = context_resolution[:login]
          logger.info "Delete session for '#{logout_login}'" if logout_login.present?
          if active_session
            saml_logout_user
          else
            clear_pending_saml_logout
          end
          redirect_to home_path
        rescue StandardError => e
          reason = "LogoutResponse validation raised #{e.class}"
          if validation_complete
            reject_saml_logout reason
          else
            reject_logout_response reason
          end
        end

        # Create a SP initiated SLO
        def sp_logout_request
          # LogoutRequest accepts plain browser requests w/o parameters
          settings = omniauth_saml_settings.dup
          transaction_token = nil

          if settings[:signout_url]
            # Since we created a new SAML request, save the transaction_id
            # to compare it with the response we get back
            logout_request = OneLogin::RubySaml::Logoutrequest.new
            transaction_id = logout_request.uuid
            logout_login = User.current.login
            logger.info "New SP SLO for userid '#{logout_login}' transactionid '#{transaction_id}'"

            settings[:name_identifier_value] = session['saml_uid'].presence || name_identifier_value
            settings[:sessionindex] = session['saml_session_index'] if session['saml_session_index'].present?

            logout_url = logout_request.create(OneLogin::RubySaml::Settings.new(settings),
                                               RelayState: home_url)
            transaction_token = RedmineSaml::SloTokenStore.create_transaction User.current
            pending_context = RedmineSaml::SloContext.pending(
              transaction_id: transaction_id,
              user_id: User.current.id,
              token: transaction_token,
              login: logout_login,
              settings: settings
            )
            saml_logout_user
            session[:transaction_id] = transaction_id
            session[:saml_logout_pending] = true
            session[:saml_logout_login] = logout_login
            session[:saml_logout_context] = pending_context
            slo_cookie.write_pending pending_context
            redirect_to logout_url, allow_other_host: true
          else
            logger.info 'SLO IdP Endpoint not found in settings, executing then a normal logout'
            saml_logout_user
            redirect_to home_path
          end
        rescue StandardError => e
          RedmineSaml::SloTokenStore.destroy_transaction transaction_token
          logger.warn "SP initiated SAML logout failed: #{e.class}"
          saml_logout_user
          redirect_to home_path
        end

        # Manage SLS response
        def redirect_after_saml_logout
          unless saml_redirect_binding_request? || saml_post_binding_request?
            return reject_saml_logout 'unsupported SAML logout HTTP method'
          end

          if params[:SAMLRequest].present? && params[:SAMLResponse].blank?
            idp_logout_request
          elsif params[:SAMLResponse].present? && params[:SAMLRequest].blank?
            process_logout_response
          else
            reject_saml_logout 'exactly one SAML logout message is required'
          end
        end

        private

        def handle_saml_inactive_user(user)
          if RedmineSaml.replace_redmine_login?
            message = user.registered? ? :notice_account_pending : :notice_account_locked
            render_error message: message, status: 403
          else
            handle_inactive_user user
          end
        end

        def require_saml_enabled
          redirect_to signin_url unless RedmineSaml.enabled?
        end

        def require_saml_sudo_reauth_available
          return if RedmineSaml::SudoReauth.available? session: session

          render_error message: :error_saml_sudo_reauth_unavailable, status: 403
        end

        # The Sudo setup_phase extension classified this callback before
        # omniauth-saml touched it, so its verdict is simply read back here.
        # Once this returns true the request never falls back to the normal
        # login path, so a Sudo Response cannot reach handle_active_user, not
        # even after its transaction was consumed and not even in a browser
        # session that never started one.
        def saml_sudo_reauth_callback?
          RedmineSaml::SudoReauth.callback? env: request.env, session: session
        end

        def saml_sudo_reauth_pending?
          RedmineSaml::SudoReauth.pending? session: session
        end

        # The session-side context, its user binding and its server-side Token
        # must all still be valid before a later tab is treated as a follower.
        # A malformed, stale or expired context therefore falls through to the
        # existing cancellation path and a fresh transaction can start.
        def active_saml_sudo_reauth_transaction
          RedmineSaml::SudoReauth.active_transaction(
            session: session,
            settings: omniauth_saml_settings,
            user_id: User.current.id
          )
        end

        # The Sudo setup_phase extension fails a Sudo callback closed with a
        # stable message, so /auth/failure recognises it even when no
        # transaction is left in the session. The normal SAML login failure
        # path is unchanged.
        def saml_sudo_reauth_failure?
          RedmineSaml::SudoReauth.failure_message?(params[:message]) || saml_sudo_reauth_pending?
        end

        # Splits the callback into a fallible preparation and a commit that only
        # writes to the response.
        #
        # Everything that can fail runs first and is fully rollback safe: a
        # rejection there leaves the Sudo timestamp untouched, writes no SLO
        # cookie, and restores the SAML session identifiers. Once the commit
        # starts, the transaction is a success and is never rolled back, so no
        # combination of a refreshed Sudo timestamp with restored identifiers,
        # or of a rewritten SLO cookie with restored identifiers, can occur.
        def handle_saml_sudo_reauth_callback
          prepared = prepare_saml_sudo_reauth_success
          return reject_saml_sudo_reauth prepared[:reason] if prepared[:reason]

          commit_saml_sudo_reauth prepared
          logger.info "SAML sudo re-authentication for '#{User.current.login}' succeeded"
          redirect_to prepared[:return_path]
        end

        def prepare_saml_sudo_reauth_success
          context = RedmineSaml::SudoContext.load_context saml_sudo_reauth_state,
                                                          settings: omniauth_saml_settings
          reason = saml_sudo_reauth_rejection_reason context
          return { reason: reason } if reason

          # The IdP may have issued a new NameID or SessionIndex. They are only
          # adopted once the transaction proved it is the same Redmine user, so
          # the SAML identity is resolved here and the SLO context is built
          # from it. It is serialized here as well, so that the commit only has
          # to perform the cookie write itself.
          identity = saml_sudo_reauth_identity
          slo_context = build_active_slo_context name_id: identity['saml_uid'],
                                                 session_index: identity['saml_session_index']
          { return_path: saml_sudo_reauth_return_path(context),
            identity: identity,
            slo_payload: slo_context && RedmineSaml::SloContext.dump(slo_context) }
        rescue StandardError => e
          { reason: "sudo re-authentication raised #{e.class}" }
        end

        # The SAML identity the session keeps after a successful transaction.
        #
        # A NameID or SessionIndex the new Response carries is adopted, which
        # is the existing behaviour. One it does not carry must not erase what
        # the session had before: omniauth-saml writes nil for a missing NameID
        # or SessionIndex, and a successful Sudo re-authentication may only
        # refresh the Sudo timestamp, never degrade the session identity. Each
        # of the two falls back on its own, so a Response that renews only one
        # of them keeps the other.
        def saml_sudo_reauth_identity
          snapshot = RedmineSaml::SudoReauth.previous_saml_session(request.env) || {}
          { 'saml_uid' => session['saml_uid'].presence || snapshot['saml_uid'],
            'saml_session_index' => session['saml_session_index'].presence || snapshot['saml_session_index'] }
        end

        # The success boundary. Only writes to the response, and only the three
        # writes below.
        #
        # The SLO cookie is written first. Its write is atomic: Rails encrypts
        # and size checks the value before it touches the cookie jar, so a
        # failure leaves the previous cookie in place. Only that single failure
        # is rolled back, by restoring the SAML session identifiers, which keeps
        # the identifiers, the SLO cookie and the Sudo timestamp consistent.
        #
        # Once the cookie write succeeded nothing is rolled back any more. The
        # two writes that follow are plain session assignments, and the logging
        # and redirect after them are outside any rescue, so a refreshed Sudo
        # timestamp can never be combined with restored identifiers. The
        # identity is written after the cookie so that both describe the same
        # NameID and SessionIndex.
        #
        # The protected action is not resumed here, so SudoMode.active! is not
        # needed: the next request revalidates the timestamp on its own.
        def commit_saml_sudo_reauth(prepared)
          write_saml_sudo_reauth_slo_context prepared[:slo_payload]
          apply_saml_sudo_reauth_identity prepared[:identity]
          update_sudo_timestamp!
        end

        def apply_saml_sudo_reauth_identity(identity)
          return if identity.blank?

          restore_saml_sudo_reauth_value 'saml_uid', identity['saml_uid']
          restore_saml_sudo_reauth_value 'saml_session_index', identity['saml_session_index']
        end

        def write_saml_sudo_reauth_slo_context(payload)
          return if payload.blank?

          slo_cookie.write_active_payload payload
        rescue StandardError
          # The cookie was not written, so the identifiers captured before
          # omniauth-saml overwrote them are restored to match it again.
          restore_saml_sudo_reauth_session nil
          raise
        end

        def saml_sudo_reauth_rejection_reason(context)
          return 'missing sudo transaction' if context.blank?

          relay_nonce = RedmineSaml::SudoReauth.relay_state_nonce params[:RelayState]
          return 'RelayState nonce mismatch' unless RedmineSaml::SudoContext.matching_nonce? context, relay_nonce

          # ruby-saml only validates InResponseTo when it was given a request
          # ID. Requiring the ID it actually used keeps this fail-closed even if
          # the Sudo setup_phase extension did not run.
          validated_request_id = RedmineSaml::SudoReauth.validated_request_id request.env
          unless RedmineSaml::SudoContext.matching_request_id? context, validated_request_id
            return 'InResponseTo was not validated for this transaction'
          end

          # The Sudo setup_phase extension captures the pre-overwrite SAML
          # session snapshot before it arms InResponseTo validation, so a
          # validated request ID always comes with a snapshot. Fail closed if
          # that ever stops being true, because the commit relies on the
          # snapshot to roll back.
          snapshot = RedmineSaml::SudoReauth.previous_saml_session request.env
          return 'missing pre-overwrite SAML session snapshot' if snapshot.nil?

          # Consumed before the identity checks so that a rejected transaction
          # cannot be retried with the same assertion.
          return 'stale sudo transaction' unless RedmineSaml::SudoTokenStore.consume_transaction context

          auth = request.env['omniauth.auth']
          return 'missing SAML authentication' if auth.blank?
          return 'no active SAML session' unless User.current.logged? && session[:logged_in_with_saml]
          return 'sudo transaction user mismatch' unless context['user_id'] == User.current.id

          saml_sudo_reauth_user_rejection_reason auth
        end

        # Resolves the assertion to an existing Redmine user without any side
        # effect: no user creation, no attribute update, no login hook.
        def saml_sudo_reauth_user_rejection_reason(auth)
          user = User.find_from_omniauth_saml auth
          return 'SAML user could not be resolved' if user.blank?
          return 'SAML user is not active' unless user.active?
          return 'SAML user mismatch' unless user.id == User.current.id

          nil
        end

        def reject_saml_sudo_reauth(reason)
          state = saml_sudo_reauth_state
          logger.warn "SAML sudo re-authentication rejected: #{reason}"
          restore_saml_sudo_reauth_session state
          RedmineSaml::SudoTokenStore.destroy_transaction state
          flash[:error] = l :error_saml_sudo_reauth_failed
          redirect_to saml_sudo_reauth_return_path(state)
        end

        def cancel_saml_sudo_reauth
          return unless RedmineSaml::SudoReauth.enabled?

          state = saml_sudo_reauth_state
          return if state.blank?

          RedmineSaml::SudoTokenStore.destroy_transaction state
          logger.info 'Cancelled the pending SAML sudo re-authentication'
        end

        # Reads and removes the session side transaction state. Removing it here
        # makes the session side single use; RedmineSaml::SudoTokenStore adds
        # the atomic server side single use.
        def saml_sudo_reauth_state
          unless instance_variable_defined? :@saml_sudo_reauth_state
            @saml_sudo_reauth_state =
              saml_sudo_reauth_state_hash session.delete(RedmineSaml::SudoReauth::SESSION_KEY)
          end
          @saml_sudo_reauth_state
        end

        def saml_sudo_reauth_state_hash(value)
          RedmineSaml::SudoReauth.transaction_state value
        end

        # omniauth-saml overwrites session['saml_uid'] and
        # session['saml_session_index'] before this controller runs, so a
        # rejected transaction must not leave the foreign values behind.
        #
        # The snapshot the Sudo setup_phase extension took in this very request
        # is the authoritative source and is preferred. It is unavailable on
        # /auth/failure, which the browser reaches as a new request, so the
        # snapshot stored when the transaction started is used there. The raw
        # session state is used so an expired transaction can still be rolled
        # back.
        def restore_saml_sudo_reauth_session(state)
          snapshot = RedmineSaml::SudoReauth.previous_saml_session(request.env) || state
          return if snapshot.blank?

          restore_saml_sudo_reauth_value 'saml_uid', snapshot['saml_uid']
          restore_saml_sudo_reauth_value 'saml_session_index', snapshot['saml_session_index']
        end

        def restore_saml_sudo_reauth_value(key, value)
          if value.is_a?(String) && value.present?
            session[key] = value
          else
            session.delete key
          end
        end

        def saml_sudo_reauth_return_path(state)
          return_url = state.is_a?(Hash) ? state['return_url'] : nil
          validate_back_url(return_url.to_s) || home_path
        end

        # The sessionStorage key of the continuation this page is about. It is
        # a storage identifier rather than a secret, but only the generated
        # shape is ever echoed back into the page.
        def saml_sudo_continuation_key
          key = params[:key].to_s
          key if RedmineSaml::SudoContinuation.key? key
        end

        # The continuation is bound to this secret, so a continuation of another
        # login session is rejected even for the same user. Read only here: a
        # session that never created one simply has nothing to resume.
        def saml_sudo_continuation_secret
          session[RedmineSaml::SudoContinuation::SESSION_KEY]
        end

        # Rendered without the restore script, so a continuation that cannot be
        # read never puts the page into a submit loop.
        def render_saml_sudo_resume_unavailable
          @saml_sudo_continuation_unavailable = true
          logger.info 'SAML sudo continuation could not be restored'
          render 'saml/sudo_mode/resume'
        end

        def active_saml_logout_session?
          RedmineSaml.enabled? && session[:logged_in_with_saml] && User.current.logged?
        end

        def valid_saml_signature_parameters?
          return params[:Signature].present? && params[:SigAlg].present? if saml_redirect_binding_request?

          saml_post_binding_request?
        end

        def saml_redirect_binding_request?
          request.request_method == 'GET'
        end

        def saml_post_binding_request?
          request.request_method == 'POST'
        end

        def valid_saml_message_size?(message, settings)
          message.to_s.bytesize <= settings.message_max_bytesize
        end

        def valid_saml_message_context?(message, settings)
          expected_issuer = settings.idp_entity_id.to_s
          issuer = message.issuer.to_s
          expected_destination = expected_saml_destination settings
          destination = message.document.root&.attributes&.[]('Destination').to_s

          issuer.present? &&
            (expected_issuer.blank? || issuer == expected_issuer) &&
            expected_destination.present? &&
            destination == expected_destination
        end

        def expected_saml_destination(settings)
          configured = settings.single_logout_service_url.to_s
          return configured if configured.present?

          derived_saml_destination settings
        end

        # alphanodes 1.0.6 initializers may omit single_logout_service_url, which
        # 1.0.6 never used for any SLO decision. Derive the SP SLS endpoint from
        # assertion_consumer_service_url, required since 1.0.6, instead of
        # weakening the Destination check. Returns an empty String when the ACS
        # URL does not identify this plugin's callback endpoint, so that the
        # caller's present? guard still rejects the message.
        def derived_saml_destination(settings)
          acs = settings.assertion_consumer_service_url.to_s
          return '' unless acs.end_with? RedmineSaml::CALLBACK_PATH

          "#{acs.delete_suffix RedmineSaml::CALLBACK_PATH}#{RedmineSaml::LOGOUT_SERVICE_PATH}"
        end

        def valid_saml_name_id?(name_id)
          expected_name_id = session['saml_uid'].presence || name_identifier_value.to_s
          return false if name_id.blank? || expected_name_id.blank?

          ActiveSupport::SecurityUtils.secure_compare name_id.to_s, expected_name_id
        end

        def valid_saml_session_index?(requested_session_indexes)
          return true if requested_session_indexes.empty?

          session['saml_session_index'].present? && requested_session_indexes.include?(session['saml_session_index'])
        end

        def valid_post_saml_signature?(document, settings)
          return true if saml_redirect_binding_request?
          return false unless saml_post_binding_request?

          RedmineSaml::SloPostSignature.valid? document, settings: settings
        end

        def reject_idp_logout_request(reason)
          reject_saml_logout reason, compatibility_error: 'IdP initiated LogoutRequest was not valid!'
        end

        def reject_logout_response(reason)
          reject_saml_logout reason, compatibility_error: 'The SAML Logout Response is invalid'
        end

        def reject_saml_logout(reason, compatibility_error: nil)
          logger.warn "SAML logout rejected: #{reason}"
          logger.error compatibility_error if compatibility_error
          render_error message: 'Invalid SAML logout request or response', status: 400
        end

        def clear_pending_saml_logout
          session.delete :transaction_id
          session.delete :saml_logout_pending
          session.delete :saml_logout_login
          session.delete :saml_logout_context
          slo_cookie.delete_pending
        end

        def saml_logout_user
          logout_user
          reset_session
          clear_slo_cookies
        end

        def issue_active_slo_context
          context = build_active_slo_context
          return unless context

          slo_cookie.write_active context
        end

        # Everything that can fail while producing the active SLO context: a
        # Token lookup and the digest computation. Split out so that the Sudo
        # callback can run it before it commits anything.
        def build_active_slo_context(name_id: session['saml_uid'], session_index: session['saml_session_index'])
          return if name_id.blank?

          token = RedmineSaml::SloTokenStore.session_token user_id: session[:user_id], value: session[:tk]
          return unless token

          RedmineSaml::SloContext.active(
            user_id: session[:user_id],
            token: token,
            name_id: name_id,
            session_index: session_index,
            settings: omniauth_saml_settings
          )
        end

        def active_slo_context
          return unless saml_post_binding_request?
          return unless slo_cookie.active_present?

          RedmineSaml::SloContext.load_active slo_cookie.read_active, settings: omniauth_saml_settings
        end

        def resolve_saml_logout_response_context
          active_session = active_saml_logout_session?
          pending_session = session[:saml_logout_pending] && User.current.anonymous?
          context_available = active_session || pending_session || saml_post_binding_request?
          return { error: 'no active or pending SAML logout' } unless context_available

          if active_session
            return {
              active_session: true,
              transaction_id: session[:transaction_id],
              login: User.current.login
            }
          end

          session_context = pending_session && RedmineSaml::SloContext.load_pending(
            session[:saml_logout_context],
            settings: omniauth_saml_settings,
            enforce_expiration: false
          )
          cookie_present = slo_cookie.pending_present?
          cookie_context = if cookie_present
                             RedmineSaml::SloContext.load_pending(
                               slo_cookie.read_pending,
                               settings: omniauth_saml_settings
                             )
                           end

          if pending_session
            valid_cookie_context = cookie_context if RedmineSaml::SloTokenStore.valid_transaction cookie_context
            if valid_cookie_context
              return { error: 'conflicting SAML logout context' } unless legacy_pending_matches_cookie? valid_cookie_context
              if session_context && !RedmineSaml::SloContext.matching_pending_contexts?(session_context, valid_cookie_context)
                return { error: 'conflicting SAML logout context' }
              end
            end

            return {
              active_session: false,
              transaction_id: session[:transaction_id],
              login: session[:saml_logout_login],
              cleanup_context: session_context || valid_cookie_context
            }
          end

          return { error: 'invalid SAML logout cookie' } if cookie_present && cookie_context.blank?
          return { error: 'no pending SAML logout cookie' } unless saml_post_binding_request? && cookie_context

          pending_resolution cookie_context, fallback: true
        end

        def pending_resolution(context, fallback:)
          {
            active_session: false,
            fallback: fallback,
            context: context,
            transaction_id: context['transaction_id'],
            login: context['login']
          }
        end

        def legacy_pending_matches_cookie?(context)
          session[:transaction_id].to_s == context['transaction_id'].to_s &&
            session[:saml_logout_login].to_s == context['login'].to_s
        end

        def slo_cookie
          @slo_cookie ||= RedmineSaml::SloCookie.new request: request, cookies: cookies
        end

        def clear_slo_cookies
          slo_cookie.delete_all
        end

        def clear_redmine_session_cookie
          configured_options = Rails.application.config.session_options.to_h.symbolize_keys
          runtime_options = request.session_options.to_hash.symbolize_keys
          cookie_name = configured_options[:key] || runtime_options[:key]
          return if cookie_name.blank?

          cookie_options = configured_options.merge(runtime_options)
                                             .slice(:path, :domain, :secure, :httponly, :same_site)
          cookie_options.delete :domain if cookie_options[:domain].nil?
          cookies[cookie_name] = cookie_options.merge value: '', expires: 1.year.ago
        end

        def clear_redmine_autologin_cookie
          secure = Redmine::Configuration['autologin_cookie_secure']
          secure = request.ssl? if secure.nil?
          path = Redmine::Configuration['autologin_cookie_path'] ||
                 RedmineApp::Application.config.relative_url_root || '/'
          cookies[autologin_cookie_name] = {
            value: '',
            expires: 1.year.ago,
            path: path,
            same_site: :lax,
            secure: secure,
            httponly: true
          }
        end

        def name_identifier_value
          User.current.send RedmineSaml.configured_saml[:name_identifier_value].to_sym
        end

        def omniauth_saml_settings
          RedmineSaml.configured_saml
        end

        def saml_logout_response_settings(settings)
          settings.dup.tap do |logout_response_settings|
            response_url = settings.idp_slo_response_service_url
            logout_response_settings.idp_slo_service_url = response_url if response_url.present?
          end
        end

        def saml_logout_url(service = nil)
          logout_uri = RedmineSaml.configured_saml[:signout_url]
          logout_uri += service.to_s if logout_uri.present?
          logout_uri || home_url
        end
      end
    end
  end
end
