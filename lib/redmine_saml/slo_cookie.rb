# frozen_string_literal: true

module RedmineSaml
  class SloCookie
    ACTIVE_NAME = '__Secure-redmine_saml_slo_session'
    PENDING_NAME = '__Secure-redmine_saml_slo_transaction'

    def initialize(request:, cookies:)
      @request = request
      @cookies = cookies
    end

    def active_present?
      request.ssl? && raw_cookie_present?(ACTIVE_NAME)
    end

    def pending_present?
      request.ssl? && raw_cookie_present?(PENDING_NAME)
    end

    def read_active
      encrypted_cookies[ACTIVE_NAME]
    end

    def read_pending
      encrypted_cookies[PENDING_NAME]
    end

    def write_active(context)
      write_active_payload SloContext.dump(context)
    end

    # Writes an already serialized active context. Callers that must not
    # serialize while they are committing state can prepare the payload first
    # and only perform the cookie write here.
    def write_active_payload(payload)
      write ACTIVE_NAME, payload
    end

    def write_pending(context)
      write PENDING_NAME,
            SloContext.dump(context),
            expires: Time.current + SloTokenStore::TRANSACTION_VALIDITY
    end

    def delete_active
      delete ACTIVE_NAME
    end

    def delete_pending
      delete PENDING_NAME
    end

    def delete_all
      delete_active
      delete_pending
    end

    def path
      relative_url_root = Rails.application.config.relative_url_root.to_s.chomp '/'
      "#{relative_url_root}#{RedmineSaml::LOGOUT_SERVICE_PATH}"
    end

    private

    attr_reader :request, :cookies

    def write(name, value, expires: nil)
      return unless request.ssl?

      options = cookie_options.merge value: value
      options[:expires] = expires if expires
      encrypted_cookies[name] = options
    end

    def delete(name)
      cookies[name] = cookie_options.merge value: '', expires: 1.year.ago
    end

    def raw_cookie_present?(name)
      cookies[name].present?
    end

    def encrypted_cookies
      cookies.encrypted
    end

    def cookie_options
      {
        path: path,
        secure: true,
        httponly: true,
        same_site: :none
      }
    end
  end
end
