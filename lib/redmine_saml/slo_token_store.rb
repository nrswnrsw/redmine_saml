# frozen_string_literal: true

module RedmineSaml
  class SloTokenStore
    ACTION = 'redmine_saml_slo'
    MAX_INSTANCES = 10
    TRANSACTION_VALIDITY = 5.minutes

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

      def destroy_transaction(token)
        return unless token

        Token.where(id: token.id, user_id: token.user_id, action: ACTION, value: token.value).delete_all
      end

      def cleanup_transaction(context)
        token = find_context_token context, action: ACTION
        return false unless token

        Token.where(id: token.id, user_id: token.user_id, action: ACTION, value: token.value).delete_all == 1
      rescue StandardError
        false
      end

      def valid_transaction(context, now: Time.current)
        token = find_context_token context, action: ACTION
        return unless token
        return if token.created_on < now - TRANSACTION_VALIDITY

        token
      end

      # Reports whether this mutating operation atomically consumed the exact SLO Token.
      # rubocop:disable Naming/PredicateMethod
      def consume_transaction(context, now: Time.current)
        token = valid_transaction context, now: now
        return false unless token

        Token.where(id: token.id, user_id: token.user_id, action: ACTION, value: token.value)
             .where(created_on: (now - TRANSACTION_VALIDITY)..)
             .delete_all == 1
      end
      # rubocop:enable Naming/PredicateMethod

      def session_token(user_id:, value:)
        Token.find_by user_id: user_id, action: 'session', value: value
      end

      def valid_session(context)
        token = find_context_token context, action: 'session'
        return unless token
        return token if Rails.application.config.redmine_verify_sessions == false
        return unless User.verify_session_token context['user_id'], token.value

        token
      end

      # Reports whether this mutating operation atomically consumed the exact session Token.
      # rubocop:disable Naming/PredicateMethod
      def consume_session(context, token)
        return false unless token

        Token.where(
          id: context['token_id'],
          user_id: context['user_id'],
          action: 'session',
          value: token.value
        ).delete_all == 1
      end
      # rubocop:enable Naming/PredicateMethod

      private

      def find_context_token(context, action:)
        return unless context

        token = Token.find_by id: context['token_id'], user_id: context['user_id'], action: action
        return unless token
        return unless token.created_on.to_i == context['token_created_at']
        return unless SloContext.secure_digest_match? context['token_verifier'], SloContext.digest(token.value)

        token
      end
    end
  end
end
