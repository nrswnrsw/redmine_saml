# frozen_string_literal: true

require_relative 'authentication_gate'

module RedmineSaml
  class Base
    class << self
      attr_reader :saml

      def on_login(&block)
        @block = block
      end

      def on_login_callback
        @block ||= nil # rubocop: disable Naming/MemoizedInstanceVariableName
      end

      def saml=(val)
        @saml = ActiveSupport::HashWithIndifferentAccess.new val
      end

      def configured_saml
        raise_configure_exception unless validated_configuration?
        saml
      end

      def configure(&block)
        raise_configure_exception if block.nil?
        yield self
        validate_configuration!
      end

      def attribute_mapping_sep
        configured_saml[:attribute_mapping_sep].presence || '|'
      end

      def user_attributes_from_saml(omniauth)
        Rails.logger.info "user_attributes_from_saml: #{auth_hash_for_logging omniauth}"

        ActiveSupport::HashWithIndifferentAccess.new.tap do |h|
          required_attribute_mapping.each do |symbol|
            key = configured_saml[:attribute_mapping][symbol]
            # Get an array with nested keys: name|first will return [name, first]
            h[symbol] = key.split(attribute_mapping_sep)
                           .map { |x| [:[], x.to_sym] } # Create pair elements being :[] symbol and the key
                           .inject(omniauth.deep_symbolize_keys) do |hash, params|
                             hash&.send(*params) # For each key, apply method :[] with key as parameter
                           end
          end
        end
      end

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

      def additionals_help_items
        [{ title: 'OmniAuth SAML',
           url: 'https://github.com/omniauth/omniauth-saml#omniauth-saml',
           admin: true }]
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

      def validated_configuration?
        @validated_configuration ||= false
      end

      def required_attribute_mapping
        %i[login firstname lastname mail]
      end

      def validate_configuration!
        %i[assertion_consumer_service_url
           sp_entity_id
           idp_slo_service_url
           idp_sso_service_url
           name_identifier_format
           name_identifier_value
           attribute_mapping].each do |k|
          raise "RedmineSaml.configure requires saml.#{k} to be set" unless saml[k]
        end

        unless saml[:idp_cert_fingerprint] || saml[:idp_cert] || saml[:idp_cert_multi]
          raise 'RedmineSaml.configure requires either :idp_cert or :idp_cert_multi or :idp_cert_fingerprint to be set'
        end

        required_attribute_mapping.each do |k|
          raise "RedmineSaml.configure requires saml.attribute_mapping[#{k}] to be set" unless saml[:attribute_mapping][k]
        end

        raise 'RedmineSaml on_login must be a Proc only' if on_login_callback && !on_login_callback.is_a?(Proc)

        @validated_configuration = true

        configure_omniauth_saml_middleware
      end

      def raise_configure_exception
        raise 'RedmineSaml must be configured from an initializer. See README of redmine_saml for instructions'
      end

      def configure_omniauth_saml_middleware
        saml_options = configured_saml
        Rails.application.config.middleware.use ::RedmineSaml::AuthenticationGate
        Rails.application.config.middleware.use ::OmniAuth::Builder do
          provider :saml, saml_options
        end
      end
    end
  end
end
