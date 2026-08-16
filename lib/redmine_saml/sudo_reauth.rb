# frozen_string_literal: true

require 'securerandom'

require_relative 'sudo_context'
require_relative 'sudo_token_store'

module RedmineSaml
  # SAML re-authentication for Redmine's Sudo Mode.
  #
  # Once the Sudo timestamp expires, Redmine asks for the local Redmine
  # password, which SAML-only users do not have. A session that was created by
  # SAML can instead confirm itself against the IdP with a dedicated SAML
  # transaction that only refreshes the Sudo timestamp. The transaction is
  # built from the configured SAML settings, used unchanged, and the plugin
  # adds no authentication condition of its own. Settings that a deployment
  # changes per request through an OmniAuth :setup endpoint are the documented
  # exception: the Sudo transaction does not go through the OmniAuth request
  # phase, so it always uses the static settings.
  #
  # A Sudo transaction is also recorded server side, in the Sudo request
  # registry of RedmineSaml::SudoTokenStore. While that record is valid, a SAML
  # Response that answers a Sudo AuthnRequest is still recognised as a Sudo one
  # after the transaction was consumed or cancelled, and in a browser session
  # that never started it, which is what keeps such a Response out of the
  # normal SAML login path. The record expires with the transaction validity.
  #
  # This follows Redmine's own Sudo Mode on every supported Redmine release.
  # Redmine 7.0 enables Sudo Mode by default; 6.0 and 6.1 only do when
  # sudo_mode: true is configured. While Sudo Mode is off, every entry point
  # below returns immediately, so nothing here can be reached: no Sudo
  # transaction can be started, no SAML callback is classified, no server side
  # record is written and the Sudo Mode prompt is Redmine's own.
  module SudoReauth
    # Sudo transaction state kept in the Redmine session.
    SESSION_KEY = 'redmine_saml_sudo'

    # Binds a SAML Response to the transaction that asked for it. This is an
    # additional signal only: it travels through the browser and can be
    # dropped, so the server side request registry, not this, is what keeps a
    # Sudo Response out of the normal login path. SAML 2.0 limits RelayState to
    # 80 bytes, so the marker and the nonce are kept short.
    RELAY_STATE_MARKER = 'redmine_saml_sudo/'
    RELAY_STATE_PARAM = 'RelayState'
    SAML_RESPONSE_PARAM = 'SAMLResponse'
    NONCE_BYTES = 16

    # The single classification verdict for this request, decided once in the
    # Sudo setup_phase extension. Everything downstream reads it instead of
    # classifying the callback again from request parameters, which Rack and
    # Rails merge in opposite orders.
    ENV_CALLBACK = 'redmine_saml.sudo_callback'

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

    # Raised by the Sudo setup_phase extension to stop a Sudo callback before
    # OmniAuth::Strategies::SAML#callback_phase runs. OmniAuth::Strategy#call!
    # turns it into fail!, so callback_phase and its session writes never
    # happen.
    class CallbackRejected < StandardError
      def initialize(message = FAILURE_MESSAGE)
        super
      end
    end

    # Prepended to OmniAuth::Strategies::SAML from RedmineSaml.setup.
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
        RedmineSaml::SudoReauth.process_setup_phase env
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
        return false if ::OmniAuth::Strategies::SAML.include? SetupPhase

        ::OmniAuth::Strategies::SAML.prepend SetupPhase
        true
      end
      # rubocop:enable Naming/PredicateMethod

      # SAML Sudo re-authentication exists exactly while Redmine's own Sudo
      # Mode does. Redmine 7.0 enables Sudo Mode by default; 6.0 and 6.1 only
      # when sudo_mode: true is configured. Redmine::Configuration reads that
      # once at boot, so this is a stable answer for the whole process.
      #
      # This is the single gate of the feature: while it is false every entry
      # point returns immediately and nothing of the Sudo machinery runs.
      #
      # An explicit wrapper, so that the gate has one name of its own here.
      # rubocop:disable Rails/Delegate
      def enabled?
        ::Redmine::SudoMode.enabled?
      end
      # rubocop:enable Rails/Delegate

      # True when the current request may offer SAML Sudo re-authentication.
      def available?(session:)
        enabled? &&
          RedmineSaml.enabled? &&
          User.current.logged? &&
          session[:logged_in_with_saml].present?
      end

      # True when a Sudo transaction was started for this session. Used by the
      # OmniAuth failure endpoint, which never receives the RelayState.
      def pending?(session:)
        enabled? && session[SESSION_KEY].present?
      end

      # Returns the one live Sudo transaction owned by this Redmine login
      # session and user. This is intentionally read only: callers use it to
      # keep the existing single-flight transaction instead of replacing it
      # when another browser tab asks to start Sudo re-authentication.
      def active_transaction(session:, settings:, user_id:, now: Time.current)
        return unless enabled?
        return if session.blank?

        context = SudoContext.load_context(
          transaction_state(session[SESSION_KEY]),
          settings: settings,
          now: now
        )
        return unless context
        return unless context['user_id'] == user_id
        return unless SudoTokenStore.valid_transaction context, now: now

        context
      end

      # A SAML callback belongs to a Sudo transaction when the Sudo setup_phase
      # extension said so for this request, or when the session still holds a
      # transaction.
      #
      # The verdict is not recomputed from request parameters here. The setup
      # extension reads them through Rack, this controller side would read them
      # through Rails, and the two merge query and body parameters in opposite
      # orders, so only one of them can be the authority.
      def callback?(env:, session:)
        return false unless enabled?
        return true if env.is_a?(Hash) && env[ENV_CALLBACK]

        session.present? && session[SESSION_KEY].present?
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
      # Only this plugin's own SAML provider is ever touched, and only in its
      # request and callback phases, so the metadata endpoint, the Single
      # Logout endpoints and any other SAML provider in the same process keep
      # their current behaviour.
      def process_setup_phase(env)
        return unless enabled?

        strategy = env['omniauth.strategy']
        return unless redmine_saml_provider? strategy
        return prepare_callback_validation env if callback_phase? strategy

        cancel_pending_transaction env if request_phase? strategy
      rescue CallbackRejected
        # Deliberate fail-closed decision: must not be swallowed below.
        raise
      rescue StandardError => e
        Rails.logger.warn "SAML sudo setup phase skipped: #{e.class}"
        nil
      end

      # Classifies the SAML callback of this plugin's own provider, and arms
      # ruby-saml for a Sudo one. A normal login is never given a
      # matches_request_id.
      #
      # For a Sudo callback candidate this fails closed: without a valid
      # transaction and AuthnRequest ID it raises CallbackRejected, so
      # OmniAuth::Strategies::SAML#callback_phase never runs and omniauth-saml
      # never overwrites session['saml_uid'] / session['saml_session_index']
      # with the identifiers of a Response this session did not ask for.
      def prepare_callback_validation(env)
        return unless enabled?

        strategy = env['omniauth.strategy']
        return unless redmine_saml_provider?(strategy) && callback_phase?(strategy)
        return unless sudo_callback_candidate? env, strategy

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

      # Starting a normal SAML login supersedes a pending Sudo transaction,
      # exactly as the Rails GET bridge already does for the request it
      # renders. This covers the case where the OmniAuth request phase is
      # reached without that bridge, which would otherwise leave the pending
      # transaction behind and make the normal login callback fail as a Sudo
      # one.
      #
      # The Sudo transaction builds its own AuthnRequest directly with
      # ruby-saml and never enters the OmniAuth request phase, so this can
      # never cancel the transaction it is starting.
      #
      # The request registry entry is deliberately left in place: a Response
      # for the cancelled transaction must still be recognised as Sudo.
      def cancel_pending_transaction(env)
        session = env['rack.session']
        return if session.blank?

        state = transaction_state session[SESSION_KEY]
        session.delete SESSION_KEY
        return if state.blank?

        SudoTokenStore.destroy_transaction state
        Rails.logger.info 'Cancelled the pending SAML sudo re-authentication'
      rescue StandardError => e
        Rails.logger.warn "SAML sudo cancellation skipped: #{e.class}"
        nil
      end

      # Reads a Sudo transaction out of an untrusted session value.
      def transaction_state(value)
        return unless value.respond_to? :to_h

        hash = value.to_h.deep_stringify_keys
        return unless hash['type'] == SudoContext::TYPE

        hash
      rescue StandardError
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
        enabled? && message.to_s == FAILURE_MESSAGE
      end

      private

      # True only for the SAML provider this plugin registered.
      #
      # OmniAuth::Strategies::SAML is shared with any other SAML provider in
      # the same process, so the provider is required to serve this plugin's
      # own callback path, which a provider registered under a different name
      # or path prefix never does. callback_path is derived from the provider
      # itself, so this identifies the provider in every phase.
      #
      # Both callback_path and script_name come from OmniAuth itself, so this
      # keeps working under a relative URL root without hardcoding any path.
      def redmine_saml_provider?(strategy)
        return false unless strategy.respond_to?(:callback_path) && strategy.respond_to?(:script_name)

        strategy.callback_path == "#{strategy.script_name}#{RedmineSaml::CALLBACK_PATH}"
      end

      def callback_phase?(strategy)
        strategy.respond_to?(:on_callback_path?) && strategy.on_callback_path?
      end

      def request_phase?(strategy)
        strategy.respond_to?(:on_request_path?) && strategy.on_request_path?
      end

      # A callback is a Sudo candidate when the session still holds a raw
      # transaction entry, when the RelayState carries the Sudo marker, or when
      # the Response answers an AuthnRequest this SP issued for a Sudo
      # transaction. None of them is validated here: an expired or damaged
      # transaction still makes this a Sudo callback, and arm_sudo_callback
      # then fails it closed.
      #
      # The two session and RelayState signals are checked first. They need
      # neither the database nor the Response, so a registry that is
      # unavailable can never downgrade a callback those signals already
      # recognised. The registry then covers what they cannot: a Response
      # whose transaction was already consumed or cancelled, and a Response
      # replayed into a completely different browser session.
      #
      # The verdict is recorded in the environment so that nothing downstream
      # has to classify the callback a second time.
      def sudo_callback_candidate?(env, strategy)
        candidate = local_sudo_signal?(env, strategy) || registered_sudo_request?(strategy)
        env[ENV_CALLBACK] = true if candidate
        candidate
      end

      def local_sudo_signal?(env, strategy)
        session = env['rack.session']
        return true if session.present? && session[SESSION_KEY].present?

        relay_state_nonce(callback_relay_state(strategy)).present?
      end

      # A registry lookup that cannot answer must not turn a normal login into
      # a rejected one, so this reports "not a Sudo callback" and leaves the
      # login to the behaviour it always had.
      def registered_sudo_request?(strategy)
        request_id = callback_in_response_to strategy
        return false if request_id.blank?

        SudoTokenStore.request_registered? request_id
      rescue StandardError => e
        Rails.logger.warn "SAML sudo request registry lookup skipped: #{e.class}"
        false
      end

      # The InResponseTo of the Response, read with ruby-saml itself rather
      # than with a second XML parser, and with the settings the strategy
      # resolved for this request, so a deployment :setup that rewrote them is
      # honoured. This is the same decoding OmniAuth::Strategies::SAML performs
      # immediately afterwards, including its message size limit.
      def callback_in_response_to(strategy)
        raw_response = strategy.request.params[SAML_RESPONSE_PARAM]
        return if raw_response.blank?

        settings = ::OneLogin::RubySaml::Settings.new strategy.options
        ::OneLogin::RubySaml::Response.new(raw_response, settings: settings).in_response_to
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
