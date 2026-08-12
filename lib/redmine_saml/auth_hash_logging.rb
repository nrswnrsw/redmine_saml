# frozen_string_literal: true

module RedmineSaml
  # Builds a loggable copy of an OmniAuth SAML AuthHash.
  #
  # The AuthHash carries the ruby-saml Response object, whose Settings hold the SP
  # private keys. Only values that are safe to log are copied out: SAML attributes
  # and identifiers, and the Response XML needed for operational troubleshooting.
  # Any other object is replaced by its class name instead of being inspected.
  class AuthHashLogging
    class << self
      def auth_hash_for_logging(omniauth)
        extra = auth_hash_value omniauth, :extra
        info = auth_hash_value omniauth, :info
        provider = auth_hash_value omniauth, :provider
        raw_info = auth_hash_value extra, :raw_info
        response_object = auth_hash_value extra, :response_object
        session_index = auth_hash_value extra, :session_index
        uid = auth_hash_value omniauth, :uid
        safe_info = log_value info
        safe_raw_info = saml_attributes_for_logging raw_info
        safe_response_object = saml_response_for_logging response_object

        OmniAuth::AuthHash.new(
          provider: provider,
          uid: uid,
          info: safe_info,
          extra: {
            raw_info: safe_raw_info,
            session_index: session_index,
            response_object: safe_response_object
          }
        ).inspect
      end

      private

      def auth_hash_value(hash, key)
        return unless hash.respond_to? :[]

        key_present = hash.key? key if hash.respond_to? :key?
        return hash[key] if key_present

        hash[key.to_s]
      end

      def log_value(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested_value), result|
            result[key] = log_value nested_value
          end
        when Array
          value.map { |nested_value| log_value nested_value }
        when String, Symbol, Numeric, TrueClass, FalseClass, NilClass
          value
        else
          "[#{value.class.name}]"
        end
      end

      def saml_attributes_for_logging(raw_info)
        attributes = if raw_info.respond_to? :all
                       raw_info.all
                     else
                       raw_info
                     end
        log_value attributes
      end

      def saml_response_for_logging(response_object)
        return unless response_object.respond_to? :response

        decrypted_document = (response_object.decrypted_document&.to_s if response_object.respond_to? :decrypted_document)

        {
          response: response_object.response.to_s,
          decrypted_document: decrypted_document
        }
      end
    end
  end
end
