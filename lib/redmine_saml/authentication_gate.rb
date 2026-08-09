# frozen_string_literal: true

module RedmineSaml
  class AuthenticationGate
    AUTHENTICATION_PATHS = ['/auth/saml', RedmineSaml::CALLBACK_PATH].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      return @app.call env unless disabled_saml_authentication_path? env

      [302,
       { 'location' => "#{env['SCRIPT_NAME'].to_s.chomp('/')}/login",
         'content-type' => 'text/html; charset=utf-8',
         'content-length' => '0' },
       []]
    end

    private

    def disabled_saml_authentication_path?(env)
      AUTHENTICATION_PATHS.include?(env['PATH_INFO']) && !RedmineSaml.enabled?
    end
  end
end
