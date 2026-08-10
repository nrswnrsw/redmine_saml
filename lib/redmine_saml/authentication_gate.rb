# frozen_string_literal: true

module RedmineSaml
  class AuthenticationGate
    AUTHENTICATION_PATHS = ['/auth/saml', RedmineSaml::CALLBACK_PATH].freeze
    UNSUPPORTED_OMNIAUTH_SLO_PATHS = %w[/auth/saml/slo /auth/saml/spslo].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      return [404, { 'content-type' => 'text/plain', 'content-length' => '0' }, []] if unsupported_omniauth_slo_path? env
      return @app.call env unless disabled_saml_authentication_path? env

      [302,
       { 'location' => "#{env['SCRIPT_NAME'].to_s.chomp('/')}/login",
         'content-type' => 'text/html; charset=utf-8',
         'content-length' => '0' },
       []]
    end

    private

    def unsupported_omniauth_slo_path?(env)
      UNSUPPORTED_OMNIAUTH_SLO_PATHS.include? env['PATH_INFO']
    end

    def disabled_saml_authentication_path?(env)
      AUTHENTICATION_PATHS.include?(env['PATH_INFO']) && !RedmineSaml.enabled?
    end
  end
end
