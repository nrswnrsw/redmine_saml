# frozen_string_literal: true

require_dependency 'account_controller'

module RedmineSaml
  module Patches
    module AccountControllerPatch
      SAML_REDIRECT_QUERY_PARAMETERS = %w[SAMLRequest SAMLResponse RelayState SigAlg Signature].freeze
      SAML_REDIRECT_RAW_PARAMETERS = %w[SAMLRequest SAMLResponse RelayState SigAlg].freeze

      extend ActiveSupport::Concern

      included do
        prepend InstanceOverwriteMethods

        helper :omniauth_saml_account

        before_action :require_saml_enabled,
                      only: %i[login_with_saml_redirect login_with_saml_callback redirect_after_saml_logout]
        before_action :verify_authenticity_token,
                      except: %i[login_with_saml_callback redirect_after_saml_logout]
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

          @saml_origin = validate_back_url params[:origin].to_s
          no_store
          render 'saml/login_with_saml_redirect'
        end

        def login_with_saml_callback
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
            query_options = saml_redirect_query_options
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
            query_options = saml_redirect_query_options
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

        def saml_query_parameters
          request.query_parameters.to_h.dup
        end

        def saml_redirect_query_options
          raw_parameters = {}
          parameter_counts = Hash.new 0

          request.query_string.to_s.split('&').each do |query_component|
            encoded_name, encoded_value = query_component.split '=', 2
            name = Rack::Utils.unescape encoded_name.to_s
            next unless SAML_REDIRECT_QUERY_PARAMETERS.include? name

            parameter_counts[name] += 1
            raw_parameters[name] = encoded_value.to_s
          end

          return if parameter_counts.any? { |_name, count| count > 1 }

          {
            get_params: {
              'Signature' => saml_query_parameters['Signature']
            },
            raw_get_params: raw_parameters.slice(*SAML_REDIRECT_RAW_PARAMETERS)
          }
        end

        def valid_saml_message_size?(message, settings)
          message.to_s.bytesize <= settings.message_max_bytesize
        end

        def valid_saml_message_context?(message, settings)
          expected_issuer = settings.idp_entity_id.to_s
          issuer = message.issuer.to_s
          expected_destination = settings.single_logout_service_url.to_s
          destination = message.document.root&.attributes&.[]('Destination').to_s

          issuer.present? &&
            (expected_issuer.blank? || issuer == expected_issuer) &&
            expected_destination.present? &&
            destination == expected_destination
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
          return if session['saml_uid'].blank?

          token = RedmineSaml::SloTokenStore.session_token user_id: session[:user_id], value: session[:tk]
          return unless token

          context = RedmineSaml::SloContext.active(
            user_id: session[:user_id],
            token: token,
            name_id: session['saml_uid'],
            session_index: session['saml_session_index'],
            settings: omniauth_saml_settings
          )
          slo_cookie.write_active context
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
