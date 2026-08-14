# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class RoutingTest < Redmine::RoutingTest
  test 'routing GET /auth/:provider' do
    should_route 'GET /auth/blah' => 'account#login_with_saml_redirect', provider: 'blah'
  end

  test 'routing GET /auth/:provider/callback' do
    should_route 'GET /auth/blah/callback' => 'account#login_with_saml_callback', provider: 'blah'
  end

  test 'routing saml' do
    should_route 'GET /auth/failure' => 'account#login_with_saml_failure'
    should_route 'GET /auth/saml/sls' => 'account#redirect_after_saml_logout'
    should_route 'POST /auth/saml/sls' => 'account#redirect_after_saml_logout'

    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path '/auth/blah/sls', method: :get
    end
  end

  test 'routing saml sudo re-authentication' do
    should_route 'POST /saml/sudo_reauth' => 'account#saml_sudo_reauth'

    # The Sudo transaction is never started by a GET, and it deliberately does
    # not live under /auth/saml where the OmniAuth SAML strategy would claim it.
    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path '/saml/sudo_reauth', method: :get
    end
    assert_raises ActionController::RoutingError do
      Rails.application.routes.recognize_path '/auth/saml/sudo_reauth', method: :post
    end
  end
end
