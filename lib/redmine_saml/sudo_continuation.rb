# frozen_string_literal: true

require 'json'
require 'securerandom'

require_relative 'sudo_context'

module RedmineSaml
  # Browser side continuation of the request that triggered a SAML Sudo Mode
  # confirmation.
  #
  # Redmine's own Sudo Mode keeps the fields of that request in hidden fields of
  # the password prompt, which works because the prompt and the resubmission are
  # the same page. A SAML confirmation leaves Redmine for the IdP, so that page
  # is gone by the time the user returns and the input is lost with it.
  #
  # The fields Redmine::SudoMode already selected are therefore sealed here into
  # one opaque string that the browser keeps in sessionStorage across the IdP
  # round trip. The continuation carries no authority of its own: it is never a
  # reason for anything to be executed, it only restores input into an ordinary
  # Redmine form that the user submits themselves, and the resumed request has
  # to pass Redmine's own Sudo Mode check like any other request.
  #
  # The seal is ActiveSupport::MessageEncryptor with a key derived from
  # secret_key_base through Rails.application.key_generator: authenticated
  # encryption, a purpose and an expiry, all of it from Rails itself. This
  # plugin implements no cryptography of its own, needs no new configuration and
  # no new table. Rails 7.2 and Rails 8.1, which cover Redmine 6.0, 6.1 and 7.0,
  # behave identically here: a tampered or foreign message raises InvalidMessage
  # and a wrong purpose or an expired message decrypts to nil.
  class SudoContinuation
    VERSION = 1
    PURPOSE = 'redmine_saml/sudo_continuation'

    # Per login session secret that binds a continuation to the session it was
    # created in. Written only when a continuation is actually created, so a
    # Redmine that never shows a SAML Sudo confirmation never stores it, and
    # removed with the rest of the session by reset_session.
    SESSION_KEY = 'redmine_saml_sudo_continuation'
    SECRET_BYTES = 16

    # Long enough for an IdP round trip that includes a second factor, short
    # enough that a forgotten continuation stops working on its own. This is a
    # cleanup bound rather than an authorisation window: what decides whether
    # the resumed request runs is Redmine's own Sudo Mode timestamp.
    VALIDITY = 15.minutes

    # Only a request Redmine itself would have resubmitted is continued. A GET
    # carries no input worth keeping and is left exactly as it was in 1.2.0.
    RESUMABLE_METHODS = %w[POST PUT PATCH DELETE].freeze

    # Framework parameters are never resubmitted from a continuation. Redmine
    # already drops them when it picks the fields itself; dropping them here as
    # well makes sure a stale CSRF token or a second _method can never be
    # restored into the form that resumes the request.
    RESERVED_FIELDS = %w[authenticity_token _method utf8 sudo_password controller action].freeze

    # Guards against sealing something no browser should be asked to keep.
    # Redmine form fields are text; a real upload never reaches this point,
    # see serializable_fields.
    MAX_FIELDS_BYTES = 512_000
    MAX_FIELD_DEPTH = 16

    # Identifies one continuation in the sessionStorage of one browser tab, so
    # that a second confirmation in the same tab cannot overwrite the input of
    # the first one. It is a storage key, not a secret.
    KEY_BYTES = 16
    KEY_PATTERN = /\A[0-9a-f]{32}\z/

    # Mirrors the relative path rule of Redmine's own validate_back_url, with
    # backslashes excluded as well. The path is authenticated by the seal, so
    # this is a second line of defence rather than the first one.
    LOCAL_PATH_PATTERN = %r{\A/(?:[^/\\]|\z)}

    # Raised while normalising fields that cannot be represented as JSON, such
    # as an ActionDispatch::Http::UploadedFile.
    class UnsupportedField < StandardError; end

    class << self
      def generate_key
        SecureRandom.hex KEY_BYTES
      end

      def generate_secret
        SecureRandom.hex SECRET_BYTES
      end

      def key?(value)
        value.to_s.match? KEY_PATTERN
      end

      def resumable_method?(request_method)
        RESUMABLE_METHODS.include? request_method.to_s.upcase
      end

      # The fields Redmine::SudoMode selected, as plain JSON safe data, or nil
      # when this request cannot be continued.
      #
      # A raw multipart upload is the case that is deliberately refused. Its
      # bytes belong neither in a browser store nor in a new server side one,
      # and serialising a stringified placeholder instead would silently change
      # what the resumed request submits. Nothing is continued then and the
      # 1.2.0 behaviour of losing the input is kept, which is also what Redmine
      # itself does with such a field in its own Sudo prompt. Redmine's own
      # attachment flow uploads files before the form is submitted and sends
      # only their tokens, so it continues normally.
      def serializable_fields(original_fields)
        hash = plain_hash original_fields
        return if hash.blank?

        fields = normalize(hash, 0).except(*RESERVED_FIELDS)
        return if fields.blank?
        return if JSON.generate(fields).bytesize > MAX_FIELDS_BYTES

        fields
      rescue StandardError
        nil
      end

      def dump(user_id:, session_secret:, request_method:, path:, fields:, now: Time.current)
        return unless resumable_method? request_method
        return if fields.blank? || session_secret.blank?
        return unless user_id.is_a?(Integer) && user_id.positive?
        return unless local_path? path

        payload = { 'version' => VERSION,
                    'user_id' => user_id,
                    'session_verifier' => SudoContext.digest(session_secret),
                    'request_method' => request_method.to_s.upcase,
                    'path' => path.to_s,
                    'fields' => fields,
                    'issued_at' => now.to_i }
        encryptor.encrypt_and_sign payload, expires_in: VALIDITY, purpose: PURPOSE
      end

      # Reads a continuation the browser handed back. Everything about it is
      # untrusted input, so this fails closed to nil on any problem: a bad seal,
      # a wrong purpose, an expired message, a different user, a different login
      # session, or a payload that does not describe a resumable request.
      def load(serialized, user_id:, session_secret:)
        return if serialized.blank? || session_secret.blank?

        payload = encryptor.decrypt_and_verify serialized.to_s, purpose: PURPOSE
        return unless payload.is_a? Hash
        return unless payload['version'] == VERSION
        return unless payload['user_id'] == user_id
        return unless SudoContext.secure_digest_match? payload['session_verifier'],
                                                       SudoContext.digest(session_secret)
        return unless resumable_method? payload['request_method']
        return unless local_path? payload['path']
        return unless payload['fields'].is_a?(Hash) && payload['fields'].present?

        payload
      rescue StandardError
        nil
      end

      def local_path?(path)
        path = path.to_s
        return false if path.blank?
        return false if path.include? '..'
        return false if path.match?(/[[:space:]]/)

        path.match? LOCAL_PATH_PATTERN
      end

      private

      def encryptor
        # Rails.application.key_generator caches derived keys, so this stays
        # cheap even though the encryptor itself is built per call.
        key = Rails.application.key_generator.generate_key PURPOSE, ActiveSupport::MessageEncryptor.key_len
        ActiveSupport::MessageEncryptor.new key, serializer: JSON
      end

      def plain_hash(original_fields)
        return original_fields.to_unsafe_h.to_h if original_fields.respond_to? :to_unsafe_h
        return original_fields.to_h if original_fields.respond_to? :to_h

        nil
      end

      def normalize(value, depth)
        raise UnsupportedField if depth > MAX_FIELD_DEPTH

        case value
        when String, Integer, Float, TrueClass, FalseClass, NilClass
          value
        when Symbol
          value.to_s
        when Array
          value.map { |item| normalize item, depth + 1 }
        when Hash
          value.each_with_object({}) { |(key, item), result| result[key.to_s] = normalize item, depth + 1 }
        else
          return normalize value.to_unsafe_h, depth + 1 if value.respond_to? :to_unsafe_h

          raise UnsupportedField
        end
      end
    end
  end
end
