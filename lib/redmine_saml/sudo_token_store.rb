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
  class SudoTokenStore
    ACTION = 'redmine_saml_sudo'
    MAX_INSTANCES = 1
    TRANSACTION_VALIDITY = SudoContext::VALIDITY

    class << self
      def register_action!
        Token.add_action ACTION,
                         max_instances: MAX_INSTANCES,
                         validity_time: proc { TRANSACTION_VALIDITY }
      end

      def create_transaction(user)
        register_action!
        Token.create! user_id: user.id, action: ACTION
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
