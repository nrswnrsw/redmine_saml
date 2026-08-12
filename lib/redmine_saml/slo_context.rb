# frozen_string_literal: true

require 'digest'
require 'json'

module RedmineSaml
  class SloContext
    VERSION = 1
    PROVIDER = 'saml'
    ACTIVE_TYPE = 'active'
    PENDING_TYPE = 'pending'
    CLOCK_SKEW = 60
    DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
    CONFIG_KEYS = %i[
      sp_entity_id
      idp_entity_id
      single_logout_service_url
      idp_slo_service_url
      idp_slo_response_service_url
    ].freeze

    class << self
      def active(user_id:, token:, name_id:, session_index:, settings:, now: Time.current)
        {
          'version' => VERSION,
          'type' => ACTIVE_TYPE,
          'user_id' => user_id,
          'token_id' => token.id,
          'token_verifier' => digest(token.value),
          'token_created_at' => token.created_on.to_i,
          'name_id_verifier' => digest(name_id),
          'session_index_present' => session_index.present?,
          'session_index_verifier' => session_index.present? ? digest(session_index) : nil,
          'issued_at' => now.to_i,
          'config_verifier' => config_digest(settings)
        }
      end

      def pending(transaction_id:, user_id:, token:, login:, settings:, now: Time.current)
        {
          'version' => VERSION,
          'type' => PENDING_TYPE,
          'transaction_id' => transaction_id,
          'user_id' => user_id,
          'token_id' => token.id,
          'token_verifier' => digest(token.value),
          'token_created_at' => token.created_on.to_i,
          'login' => login,
          'issued_at' => now.to_i,
          'config_verifier' => config_digest(settings)
        }
      end

      def dump(context)
        JSON.generate context
      end

      def load_active(serialized, settings:, now: Time.current)
        load_context serialized, type: ACTIVE_TYPE, settings: settings, now: now
      end

      def load_pending(serialized, settings:, now: Time.current, enforce_expiration: true)
        context = load_context serialized, type: PENDING_TYPE, settings: settings, now: now
        return unless context
        return if enforce_expiration && context['issued_at'] < now.to_i - SloTokenStore::TRANSACTION_VALIDITY.to_i

        context
      end

      def matching_name_id?(context, name_id)
        name_id.present? && secure_digest_match?(context['name_id_verifier'], digest(name_id))
      end

      def matching_session_indexes?(context, requested_session_indexes)
        requested_session_indexes = Array.wrap requested_session_indexes
        return true if requested_session_indexes.empty?
        return false unless context['session_index_present']

        requested_session_indexes.any? do |session_index|
          secure_digest_match? context['session_index_verifier'], digest(session_index)
        end
      end

      def matching_pending_contexts?(left, right)
        return false unless left && right

        pending_context_fields.all? do |key|
          left[key].to_s == right[key].to_s
        end
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
        values = [VERSION, PROVIDER]
        CONFIG_KEYS.each { |key| values << settings[key].to_s }
        digest JSON.generate(values)
      end

      private

      def pending_context_fields
        %w[transaction_id user_id token_id token_verifier token_created_at login issued_at config_verifier]
      end

      def load_context(serialized, type:, settings:, now:)
        context = parse serialized
        return unless context
        return unless context['version'] == VERSION && context['type'] == type
        return unless positive_integer? context['user_id']
        return unless positive_integer? context['token_id']
        return unless positive_integer? context['token_created_at']
        return unless integer? context['issued_at']
        return if context['issued_at'] > now.to_i + CLOCK_SKEW
        return unless context['token_verifier'].to_s.match? DIGEST_PATTERN
        return unless secure_digest_match? context['config_verifier'], config_digest(settings)
        return unless valid_type_fields? context, type

        context
      rescue JSON::ParserError, TypeError
        nil
      end

      def parse(serialized)
        value = serialized.is_a?(String) ? JSON.parse(serialized) : serialized
        value.to_h.deep_stringify_keys if value.respond_to? :to_h
      end

      def valid_type_fields?(context, type)
        if type == ACTIVE_TYPE
          active_fields_valid? context
        else
          pending_fields_valid? context
        end
      end

      def active_fields_valid?(context)
        return false unless context['name_id_verifier'].to_s.match? DIGEST_PATTERN
        return false unless [true, false].include? context['session_index_present']

        if context['session_index_present']
          context['session_index_verifier'].to_s.match? DIGEST_PATTERN
        else
          context['session_index_verifier'].nil?
        end
      end

      def pending_fields_valid?(context)
        context['transaction_id'].is_a?(String) && context['transaction_id'].present? &&
          context['login'].is_a?(String) && context['login'].present?
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
