# frozen_string_literal: true

require_relative 'sudo_context'

module RedmineSaml
  # Identity of the Redmine login session, for the parts of SAML Sudo
  # re-authentication whose scope is one login session rather than one user.
  #
  # Redmine already issues exactly such an identifier. start_user_session sets
  # session[:tk] to a session token backed by a Token(action: 'session') row, on
  # every supported release and on every login path including autologin. It is
  # shared by every tab of one login session and differs between login sessions
  # and devices, which is precisely the scope this feature needs. Using it means
  # no identifier, no table, no migration and no setting of this plugin's own.
  #
  # The raw token is a session secret and never leaves the server. Everything
  # derived here is a domain separated SHA-256 digest, so no value that reaches
  # a browser, a URL, a log or a SAML payload can be turned back into it, and
  # two values derived for different purposes cannot be correlated with each
  # other either.
  #
  # A session without a token is not an expected state for a SAML login session,
  # but it is never treated as an error: the callers below fall back to the
  # behaviour this plugin had before, so nothing breaks if it ever happens.
  module SudoSession
    LOCK_DOMAIN = 'redmine_saml/sudo/transaction-lock'
    CONTINUATION_DOMAIN = 'redmine_saml/sudo/continuation-binding'

    class << self
      # The raw Redmine session token of this session, or nil.
      def token(session)
        return if session.blank?

        value = read(session, :tk) || read(session, 'tk')
        value.to_s.presence
      end

      def known?(session)
        token(session).present?
      end

      # Key of the one Sudo transaction of this login session.
      def lock_value(session, length:)
        derive(session, LOCK_DOMAIN)&.slice 0, length
      end

      # Secret a continuation of this login session is bound to.
      def continuation_secret(session)
        derive session, CONTINUATION_DOMAIN
      end

      private

      def read(session, key)
        session[key]
      rescue StandardError
        nil
      end

      # The separator is a NUL byte, so that no domain and token pair can be
      # confused with another one. It is written as the Ruby escape rather than
      # as the byte itself: a literal NUL in the source would make git treat
      # this security relevant file as binary and hide it from review.
      def derive(session, domain)
        value = token session
        return if value.blank?

        SudoContext.digest "#{domain}\0#{value}"
      end
    end
  end
end
