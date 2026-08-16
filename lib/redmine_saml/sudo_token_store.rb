# frozen_string_literal: true

require_relative 'sudo_context'
require_relative 'sudo_session'

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
    LOCK_VALUE_LENGTH = REQUEST_VALUE_LENGTH

    class << self
      def register_action!
        # max_instances is what Token#delete_previous_tokens evicts by, and it
        # evicts by user and action alone, which would let one login session
        # drop the transaction of another login session of the same user. No
        # row here is ever created through that callback: both actions are
        # inserted directly, so the eviction never runs and the scope of a
        # transaction is its login session, not its user. The option is
        # registered only because Token#max_instances would otherwise be nil.
        # validity_time is the part that matters: it lets Token.destroy_expired
        # prune expired entries with everything else.
        Token.add_action ACTION,
                         max_instances: MAX_INSTANCES,
                         validity_time: proc { TRANSACTION_VALIDITY }
        Token.add_action REQUEST_ACTION,
                         max_instances: MAX_INSTANCES,
                         validity_time: proc { REQUEST_VALIDITY }
      end

      # Acquires the one Sudo transaction of a Redmine login session.
      #
      # tokens.value carries a unique index in every supported Redmine schema,
      # so inserting the login session lock value is an atomic acquisition on
      # every database Redmine supports: of any number of genuinely concurrent
      # requests exactly one inserts the row and every other one is refused by
      # the database. No advisory lock, no database specific feature, no new
      # table and nothing that depends on the session cookie, which the client
      # controls the delivery of and which cannot arbitrate between two
      # requests that both read the same snapshot.
      #
      # Scoping the value to the login session rather than to the user is what
      # keeps two login sessions of one user independent: their lock values
      # differ, so neither can evict the transaction of the other.
      #
      # Returns the Token when this caller acquired the transaction, or nil
      # when another request of the same login session already holds it.
      def acquire_transaction(user, session, now: Time.current)
        register_action!
        value = SudoSession.lock_value session, length: LOCK_VALUE_LENGTH
        return create_transaction user, now: now if value.blank?

        # An expired lock of this very login session is cleared first. It is a
        # conditional DELETE, so any number of concurrent callers may run it
        # and at most one of them still wins the INSERT below.
        expire_lock value, now: now
        insert_lock user, value, now: now
      rescue ActiveRecord::RecordNotUnique
        # Another request of this login session inserted the row first. The
        # violation was raised inside the savepoint of insert_lock and has
        # already rolled it back by the time it arrives here, so the caller's
        # transaction is untouched and usable.
        nil
      end

      # True while this login session holds a Sudo transaction, read from the
      # server side rather than from the session, so a tab whose cookie does
      # not know about a concurrently started transaction still sees it.
      def transaction_pending?(session, now: Time.current)
        value = SudoSession.lock_value session, length: LOCK_VALUE_LENGTH
        return false if value.blank?

        Token.where(action: ACTION, value: value)
             .exists?(created_on: (now - TRANSACTION_VALIDITY)..)
      end

      # Fallback for a session that carries no Redmine session token. Inserted
      # without callbacks like every other row here, so that it can never evict
      # the transaction of another login session of the same user.
      def create_transaction(user, now: Time.current)
        register_action!
        insert_token user, Token.generate_token_value, now: now
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

      # The INSERT that decides the winner, isolated in a transaction of its
      # own. Inside an open transaction that is a savepoint, which is what
      # makes losing the race survivable: PostgreSQL aborts the whole
      # transaction on a constraint violation and refuses every later
      # statement in it, so without the savepoint a losing acquisition would
      # poison the surrounding transaction of the caller. Rolling back to the
      # savepoint leaves that transaction usable.
      #
      # The violation is deliberately not rescued here. It has to leave this
      # block so that the savepoint is rolled back first; acquire_transaction
      # rescues it afterwards.
      def insert_lock(user, value, now: Time.current)
        Token.transaction requires_new: true do
          insert_token user, value, now: now
        end
      end

      def insert_token(user, value, now: Time.current)
        Token.insert!({ user_id: user.id, action: ACTION, value: value,
                        created_on: now, updated_on: now })
        Token.find_by action: ACTION, value: value
      end

      def expire_lock(value, now: Time.current)
        Token.where(action: ACTION, value: value)
             .where(created_on: ...(now - TRANSACTION_VALIDITY))
             .delete_all
      end

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
