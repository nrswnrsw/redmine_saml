# frozen_string_literal: true

require_relative 'sudo_context'

module RedmineSaml
  # Server side single use marker for a SAML Sudo re-authentication
  # transaction.
  #
  # Deleting the transaction from the Redmine session alone is not a strong
  # single use guarantee: the session lives in a cookie the client controls the
  # delivery of, and two concurrent callbacks can both read the same session
  # snapshot. A Redmine Token row gives the transaction a server side identity
  # that can be consumed with a single conditional DELETE, so exactly one
  # caller can win.
  #
  # This deliberately does not reuse RedmineSaml::SloTokenStore. It registers
  # its own Token action so that Single Logout semantics stay untouched. It
  # needs no schema change: Token.add_action registers actions at runtime and
  # the tokens table already stores user_id, action, value and created_on.
  #
  # A second Token action holds the Sudo request registry. It answers one
  # question only: was this AuthnRequest ID issued by a Sudo transaction? The
  # single use transaction Token cannot answer it, because it is consumed by
  # the very first callback, after which a replayed Sudo Response would no
  # longer be recognised as one. The registry entry therefore deliberately
  # outlives the transaction and expires on time alone.
  class SudoTokenStore
    ACTION = 'redmine_saml_sudo'
    MAX_INSTANCES = 1
    TRANSACTION_VALIDITY = SudoContext::VALIDITY

    # Registry of the AuthnRequests issued for Sudo transactions.
    #
    # Every entry a user holds within the validity window is kept: consuming
    # or cancelling one transaction must not stop a Response of an earlier one
    # from being recognised, and a user can legitimately start several
    # transactions within that window. Entries are only ever removed once they
    # expire.
    REQUEST_ACTION = 'redmine_saml_sudo_req'
    REQUEST_VALIDITY = SudoContext::VALIDITY

    # tokens.value is a unique column of 40 characters, which is also the
    # length Token.generate_token_value produces.
    REQUEST_VALUE_LENGTH = 40

    class << self
      def register_action!
        Token.add_action ACTION,
                         max_instances: MAX_INSTANCES,
                         validity_time: proc { TRANSACTION_VALIDITY }
        # max_instances is what Token#delete_previous_tokens evicts by, which
        # a registry entry must never be subject to, so it is registered only
        # because Token#max_instances would otherwise be nil. Registry entries
        # are inserted without that callback, see register_request.
        # validity_time is the part that matters here: it lets
        # Token.destroy_expired prune expired entries with everything else.
        Token.add_action REQUEST_ACTION,
                         max_instances: MAX_INSTANCES,
                         validity_time: proc { REQUEST_VALIDITY }
      end

      def create_transaction(user)
        register_action!
        Token.create! user_id: user.id, action: ACTION
      end

      # Records that this AuthnRequest ID belongs to a Sudo transaction.
      #
      # Only a digest is stored. The AuthnRequest ID itself travels through
      # the browser, so this is a lookup key rather than a secret, but there
      # is no reason to keep a value the SP does not need in clear text.
      #
      # Token#delete_previous_tokens, a before_create callback, evicts older
      # entries of the same user by count alone, which would drop an entry
      # that is still within REQUEST_VALIDITY and let the Response it covers
      # be taken for a normal login. The row is therefore inserted without
      # callbacks, which also keeps the chosen value that
      # Token#generate_new_token would otherwise replace. Expired entries of
      # the same user are pruned here instead, so the table cannot grow
      # without bound between Token.destroy_expired runs.
      def register_request(user, request_id, now: Time.current)
        register_action!
        value = request_value request_id
        raise ArgumentError, 'a sudo request registry entry needs an AuthnRequest ID' if value.blank?

        cleanup_expired_requests user, now: now
        Token.insert!({ user_id: user.id, action: REQUEST_ACTION, value: value,
                        created_on: now, updated_on: now })
        Token.find_by action: REQUEST_ACTION, value: value
      end

      # True while a Sudo transaction that issued this AuthnRequest ID is
      # still within the registry validity window, whether or not it was
      # already consumed or cancelled, and independently of any session.
      def request_registered?(request_id, now: Time.current)
        value = request_value request_id
        return false if value.blank?

        Token.where(action: REQUEST_ACTION, value: value)
             .exists?(created_on: (now - REQUEST_VALIDITY)..)
      end

      def valid_transaction(context, now: Time.current)
        token = find_context_token context
        return unless token
        return if token.created_on < now - TRANSACTION_VALIDITY

        token
      end

      # Reports whether this mutating operation atomically consumed the exact
      # Sudo transaction Token. The DELETE is a single statement, so only one
      # of any number of concurrent callbacks can see one affected row.
      # rubocop:disable Naming/PredicateMethod
      def consume_transaction(context, now: Time.current)
        token = valid_transaction context, now: now
        return false unless token

        token_scope(token)
          .where(created_on: (now - TRANSACTION_VALIDITY)..)
          .delete_all == 1
      end

      # Invalidates a transaction without requiring it to be still valid, for
      # the cancel and failure paths.
      def destroy_transaction(context)
        token = find_context_token context
        return false unless token

        token_scope(token).delete_all == 1
      end
      # rubocop:enable Naming/PredicateMethod

      private

      def cleanup_expired_requests(user, now: Time.current)
        Token.where(user_id: user.id, action: REQUEST_ACTION)
             .where(created_on: ...(now - REQUEST_VALIDITY))
             .delete_all
      end

      def request_value(request_id)
        request_id = request_id.to_s
        return if request_id.blank?

        SudoContext.digest(request_id)[0, REQUEST_VALUE_LENGTH]
      end

      def token_scope(token)
        Token.where id: token.id, user_id: token.user_id, action: ACTION, value: token.value
      end

      def find_context_token(context)
        return unless context

        token = Token.find_by id: context['token_id'], user_id: context['user_id'], action: ACTION
        return unless token
        return unless token.created_on.to_i == context['token_created_at']
        return unless SudoContext.secure_digest_match? context['token_verifier'], SudoContext.digest(token.value)

        token
      rescue StandardError
        nil
      end
    end
  end
end
