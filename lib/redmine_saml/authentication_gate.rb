# frozen_string_literal: true

module RedmineSaml
  class AuthenticationGate
    AUTHENTICATION_PATHS = ['/auth/saml', RedmineSaml::CALLBACK_PATH].freeze
    UNSUPPORTED_OMNIAUTH_SLO_PATHS = %w[/auth/saml/slo /auth/saml/spslo].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      path = normalized_omniauth_path env
      return [404, { 'content-type' => 'text/plain', 'content-length' => '0' }, []] if unsupported_omniauth_slo_path? path
      return @app.call env unless disabled_saml_authentication_path? path

      [302,
       { 'location' => "#{env['SCRIPT_NAME'].to_s.chomp '/'}/login",
         'content-type' => 'text/html; charset=utf-8',
         'content-length' => '0' },
       []]
    end

    private

    def normalized_omniauth_path(env)
      # Keep path recognition aligned with OmniAuth::Strategy#current_path.
      env['PATH_INFO'].to_s.downcase.sub %r{/$}, ''
    end

    def unsupported_omniauth_slo_path?(path)
      UNSUPPORTED_OMNIAUTH_SLO_PATHS.include? path
    end

    def disabled_saml_authentication_path?(path)
      AUTHENTICATION_PATHS.include?(path) && !RedmineSaml.enabled?
    end
  end
end
