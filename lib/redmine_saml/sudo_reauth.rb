# frozen_string_literal: true

require 'securerandom'

require_relative 'sudo_context'

module RedmineSaml
  # SAML re-authentication for Redmine's Sudo Mode.
  #
  # Redmine 7.0 enables Sudo Mode by default. Once the Sudo timestamp expires,
  # Redmine asks for the local Redmine password, which SAML-only users do not
  # have. For Redmine 7.0 and later, a session that was created by SAML can
  # instead confirm itself against the IdP with a dedicated SAML transaction
  # that only refreshes the Sudo timestamp. The transaction is built from the
  # configured SAML settings, used unchanged, and the plugin adds no
  # authentication condition of its own. Settings that a deployment changes per
  # request through an OmniAuth :setup endpoint are the documented exception:
  # the Sudo transaction does not go through the OmniAuth request phase, so it
  # always uses the static settings.
  #
  # Redmine 6.0 and 6.1 are deliberately out of scope. Every entry point below
  # reports the feature as unsupported there, the ApplicationController patch is
  # not even applied, and no Sudo transaction can be started, so those releases
  # behave exactly as they did before this feature existed.
  module SudoReauth
    # Sudo transaction state kept in the Redmine session.
    SESSION_KEY = 'redmine_saml_sudo'

    # Marks a SAML Response as belonging to a Sudo transaction even when the
    # session side state was already consumed. SAML 2.0 limits RelayState to
    # 80 bytes, so the marker and the nonce are kept short.
    RELAY_STATE_MARKER = 'redmine_saml_sudo/'
    RELAY_STATE_PARAM = 'RelayState'
    NONCE_BYTES = 16

    # Set by the Sudo setup_phase extension once ruby-saml has been told to
    # validate InResponseTo for this request. The Sudo handler requires it, so
    # an extension that did not run fails the transaction closed instead of
    # silently skipping the correlation check.
    ENV_MATCHES_REQUEST_ID = 'redmine_saml.sudo_matches_request_id'

    # SAML session identifiers as they were before omniauth-saml overwrote them
    # for this request. Captured by the Sudo setup_phase extension, which runs
    # before OmniAuth::Strategies::SAML#handle_response.
    ENV_PREVIOUS_SAML_CAPTURED = 'redmine_saml.sudo_previous_saml_captured'
    ENV_PREVIOUS_SAML_UID = 'redmine_saml.sudo_previous_saml_uid'
    ENV_PREVIOUS_SAML_SESSION_INDEX = 'redmine_saml.sudo_previous_saml_session_index'

    # Stable OmniAuth failure message for a Sudo callback that the Sudo
    # setup_phase extension refused. It ends up in the ?message= parameter of
    # /auth/failure, which is the only thing that endpoint receives.
    FAILURE_MESSAGE = 'redmine_saml_sudo_reauth'

    MINIMUM_REDMINE_MAJOR_VERSION = 7

    # Raised by the Sudo setup_phase extension to stop a Sudo callback before
    # OmniAuth::Strategies::SAML#callback_phase runs. OmniAuth::Strategy#call!
    # turns it into fail!, so callback_phase and its session writes never
    # happen.
    class CallbackRejected < StandardError
      def initialize(message = FAILURE_MESSAGE)
        super
      end
    end

    # Prepended to OmniAuth::Strategies::SAML on Redmine 7.0 and later only,
    # from RedmineSaml.setup.
    #
    # The OmniAuth :setup option is a documented part of the configuration
    # surface of this plugin, and has been since alphanodes 1.0.6, so it must
    # not be taken over. Extending setup_phase instead leaves a deployment's
    # own :setup completely untouched: super runs it with its original
    # semantics, including the callable form, the call-through form and a
    # custom :setup_path, and an error it raises still propagates unchanged.
    module SetupPhase
      def setup_phase
        super
        RedmineSaml::SudoReauth.prepare_callback_validation env
      end
    end

    class << self
      # OmniAuth::Strategies::SAML is shared by every SAML provider in the
      # process, so the module is applied once and its body decides per request
      # whether the provider is the one this plugin registered.
      #
      # Reports whether this call installed the extension.
      # rubocop:disable Naming/PredicateMethod
      def install_setup_phase!
        return false unless supported?
        return false if ::OmniAuth::Strategies::SAML.include? SetupPhase

        ::OmniAuth::Strategies::SAML.prepend SetupPhase
        true
      end
      # rubocop:enable Naming/PredicateMethod

      # SAML Sudo re-authentication is a Redmine 7.0+ feature only.
      def supported?
        ::Redmine::VERSION::MAJOR >= MINIMUM_REDMINE_MAJOR_VERSION
      end

      # True when the current request may offer SAML Sudo re-authentication.
      def available?(session:)
        supported? &&
          RedmineSaml.enabled? &&
          ::Redmine::SudoMode.enabled? &&
          User.current.logged? &&
          session[:logged_in_with_saml].present?
      end

      # True when a Sudo transaction was started for this session. Used by the
      # OmniAuth failure endpoint, which never receives the RelayState.
      def pending?(session:)
        supported? && session[SESSION_KEY].present?
      end

      # A SAML callback belongs to a Sudo transaction when either side says so.
      #
      # The session state alone would let an attacker downgrade a Sudo callback
      # into a normal login by stripping the RelayState. The RelayState marker
      # alone would stop covering a replayed SAML Response once the session
      # state has been consumed. Requiring only one of them closes both.
      def callback?(session:, relay_state:)
        return false unless supported?

        relay_state_nonce(relay_state).present? || session[SESSION_KEY].present?
      end

      def generate_nonce
        SecureRandom.hex NONCE_BYTES
      end

      def relay_state(nonce)
        "#{RELAY_STATE_MARKER}#{nonce}"
      end

      def relay_state_nonce(value)
        value = value.to_s
        return unless value.start_with? RELAY_STATE_MARKER

        value.delete_prefix(RELAY_STATE_MARKER).presence
      end

      # Runs at the end of OmniAuth::Strategy#setup_phase, which the strategy
      # calls for its request, callback and other phases.
      #
      # It only ever acts on the SAML callback of this plugin's own provider,
      # and only when that callback looks like a Sudo transaction, so the
      # normal login request, the normal login callback, the metadata endpoint,
      # the Single Logout endpoints and any other SAML provider in the same
      # process keep their current behaviour, and a normal login is never given
      # a matches_request_id.
      #
      # For a Sudo callback candidate this fails closed: without a valid
      # transaction and AuthnRequest ID it raises CallbackRejected, so
      # OmniAuth::Strategies::SAML#callback_phase never runs and omniauth-saml
      # never overwrites session['saml_uid'] / session['saml_session_index']
      # with the identifiers of a Response this session did not ask for.
      def prepare_callback_validation(env)
        return unless supported?

        strategy = env['omniauth.strategy']
        return unless redmine_saml_callback_phase? strategy
        return unless sudo_callback_candidate? strategy, env['rack.session']

        arm_sudo_callback env, strategy
      rescue CallbackRejected
        # Deliberate fail-closed decision: must not be swallowed below.
        raise
      rescue StandardError => e
        # Only reachable while it is still unknown whether this is a Sudo
        # callback, or for a normal login. Keep the existing behaviour there.
        Rails.logger.warn "SAML sudo callback setup skipped: #{e.class}"
        nil
      end

      # The AuthnRequest ID that ruby-saml actually validated InResponseTo
      # against during this request, or nil when no validation was requested.
      def validated_request_id(env)
        env[ENV_MATCHES_REQUEST_ID].presence
      end

      # SAML session identifiers as they were before omniauth-saml overwrote
      # them during this request, or nil when nothing was captured. A captured
      # value of nil means the key did not exist and has to be removed again.
      def previous_saml_session(env)
        return unless env.is_a? Hash
        return unless env[ENV_PREVIOUS_SAML_CAPTURED]

        { 'saml_uid' => env[ENV_PREVIOUS_SAML_UID],
          'saml_session_index' => env[ENV_PREVIOUS_SAML_SESSION_INDEX] }
      end

      def failure_message?(message)
        supported? && message.to_s == FAILURE_MESSAGE
      end

      private

      # True only for the callback phase of the SAML provider this plugin
      # registered.
      #
      # OmniAuth::Strategy#on_callback_path? compares OmniAuth's own
      # current_path with its callback_path, so it recognises the callback
      # phase of whichever provider is running. That alone is not enough here,
      # because OmniAuth::Strategies::SAML is shared with any other SAML
      # provider in the same process. The provider is therefore also required
      # to serve this plugin's own callback path, which a provider registered
      # under a different name or path prefix never does.
      #
      # Both callback_path and script_name come from OmniAuth itself, so this
      # keeps working under a relative URL root without hardcoding any path.
      def redmine_saml_callback_phase?(strategy)
        return false unless strategy.respond_to?(:on_callback_path?) && strategy.on_callback_path?
        return false unless strategy.respond_to?(:callback_path) && strategy.respond_to?(:script_name)

        strategy.callback_path == "#{strategy.script_name}#{RedmineSaml::CALLBACK_PATH}"
      end

      # A callback is a Sudo candidate when the session still holds a raw
      # transaction entry or the RelayState carries the Sudo marker. The entry
      # is not validated here: an expired or damaged one still makes this a
      # Sudo callback, and arm_sudo_callback then fails it closed.
      #
      # The session is checked first so that recognising a pending transaction
      # never depends on reading the request body.
      def sudo_callback_candidate?(strategy, session)
        return true if session.present? && session[SESSION_KEY].present?

        relay_state_nonce(callback_relay_state(strategy)).present?
      end

      def callback_relay_state(strategy)
        strategy.request.params[RELAY_STATE_PARAM]
      end

      # Everything from here on happens after this request was identified as a
      # Sudo callback, so any unexpected error fails the transaction closed
      # instead of letting the callback continue unvalidated.
      def arm_sudo_callback(env, strategy)
        capture_previous_saml_session env

        context = SudoContext.load_context env['rack.session'][SESSION_KEY],
                                           settings: RedmineSaml.configured_saml
        request_id = context && context['request_id']
        raise CallbackRejected if request_id.blank?

        strategy.options[:matches_request_id] = request_id
        env[ENV_MATCHES_REQUEST_ID] = request_id
      rescue CallbackRejected
        raise
      rescue StandardError => e
        Rails.logger.warn "SAML sudo callback setup failed closed: #{e.class}"
        raise CallbackRejected
      end

      def capture_previous_saml_session(env)
        return if env[ENV_PREVIOUS_SAML_CAPTURED]

        session = env['rack.session']
        env[ENV_PREVIOUS_SAML_UID] = session && session['saml_uid']
        env[ENV_PREVIOUS_SAML_SESSION_INDEX] = session && session['saml_session_index']
        env[ENV_PREVIOUS_SAML_CAPTURED] = true
      end
    end
  end
end
