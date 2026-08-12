# frozen_string_literal: true

module RedmineSaml
  # Rebuilds the signed query of an HTTP-Redirect binding SAML logout message.
  #
  # ruby-saml verifies the Redirect binding signature against the query string as
  # the IdP encoded it, so the percent encoding of the signed parts must be kept
  # instead of being re-encoded from the parsed parameters. A duplicated signed
  # parameter is rejected so a second occurrence cannot shadow the signed value.
  class RedirectBinding
    SAML_REDIRECT_QUERY_PARAMETERS = %w[SAMLRequest SAMLResponse RelayState SigAlg Signature].freeze
    SAML_REDIRECT_RAW_PARAMETERS = %w[SAMLRequest SAMLResponse RelayState SigAlg].freeze

    class << self
      # Returns nil when a signed query parameter is duplicated, so that the
      # caller rejects the message.
      def query_options(request)
        raw_parameters = {}
        parameter_counts = Hash.new 0

        request.query_string.to_s.split('&').each do |query_component|
          encoded_name, encoded_value = query_component.split '=', 2
          name = Rack::Utils.unescape encoded_name.to_s
          next unless SAML_REDIRECT_QUERY_PARAMETERS.include? name

          parameter_counts[name] += 1
          raw_parameters[name] = encoded_value.to_s
        end

        return if parameter_counts.any? { |_name, count| count > 1 }

        {
          get_params: {
            'Signature' => request.query_parameters['Signature']
          },
          raw_get_params: raw_parameters.slice(*SAML_REDIRECT_RAW_PARAMETERS)
        }
      end
    end
  end
end
