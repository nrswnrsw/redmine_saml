# frozen_string_literal: true

require 'digest'
require 'json'

module RedmineSaml
  # Session side state of a SAML Sudo re-authentication transaction.
  #
  # Mirrors RedmineSaml::SloContext: secrets are stored as SHA-256 digests and
  # compared with a constant time comparison, and the context is bound to the
  # SAML configuration it was issued for. The AuthnRequest ID is the one value
  # kept in clear text, because ruby-saml needs it as :matches_request_id.
  class SudoContext
    VERSION = 1
    TYPE = 'sudo'
    CLOCK_SKEW = 60
    DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
    VALIDITY = 5.minutes
    CONFIG_KEYS = %i[
      sp_entity_id
      idp_entity_id
      idp_sso_service_url
      assertion_consumer_service_url
    ].freeze

    class << self
      # saml_uid and saml_session_index are the values that were active before
      # the transaction started. omniauth-saml overwrites the live session
      # values before the Rails controller runs, so a failed transaction can
      # only restore them from this snapshot.
      def build(user_id:, request_id:, nonce:, token:, return_url:,
                saml_uid:, saml_session_index:, settings:, now: Time.current)
        {
          'version' => VERSION,
          'type' => TYPE,
          'user_id' => user_id,
          'request_id' => request_id,
          'nonce_verifier' => digest(nonce),
          'token_id' => token.id,
          'token_verifier' => digest(token.value),
          'token_created_at' => token.created_on.to_i,
          'return_url' => return_url,
          'saml_uid' => saml_uid,
          'saml_session_index' => saml_session_index,
          'issued_at' => now.to_i,
          'config_verifier' => config_digest(settings)
        }
      end

      def load_context(serialized, settings:, now: Time.current)
        context = parse serialized
        return unless context
        return unless context['version'] == VERSION && context['type'] == TYPE
        return unless positive_integer? context['user_id']
        return unless positive_integer? context['token_id']
        return unless positive_integer? context['token_created_at']
        return unless integer? context['issued_at']
        return if context['issued_at'] > now.to_i + CLOCK_SKEW
        return if context['issued_at'] < now.to_i - VALIDITY.to_i
        return unless context['request_id'].is_a?(String) && context['request_id'].present?
        return unless context['token_verifier'].to_s.match? DIGEST_PATTERN
        return unless context['nonce_verifier'].to_s.match? DIGEST_PATTERN
        return unless secure_digest_match? context['config_verifier'], config_digest(settings)

        context
      rescue TypeError
        nil
      end

      def matching_nonce?(context, nonce)
        return false unless context

        nonce.present? && secure_digest_match?(context['nonce_verifier'], digest(nonce))
      end

      def matching_request_id?(context, request_id)
        return false unless context

        expected = context['request_id'].to_s
        return false if expected.blank? || request_id.blank?

        ActiveSupport::SecurityUtils.secure_compare expected, request_id.to_s
      end

      def digest(value)
        Digest::SHA256.hexdigest value.to_s.b
      end

      def secure_digest_match?(expected, actual)
        return false unless expected.to_s.match? DIGEST_PATTERN
        return false unless actual.to_s.match? DIGEST_PATTERN

        ActiveSupport::SecurityUtils.secure_compare expected, actual
      end

      def config_digest(settings)
        values = [VERSION, TYPE]
        CONFIG_KEYS.each { |key| values << settings[key].to_s }
        digest JSON.generate(values)
      end

      private

      def parse(serialized)
        return unless serialized.respond_to? :to_h

        serialized.to_h.deep_stringify_keys
      end

      def positive_integer?(value)
        integer?(value) && value.positive?
      end

      def integer?(value)
        value.is_a? Integer
      end
    end
  end
end
