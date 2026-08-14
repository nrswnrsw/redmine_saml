# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class SloCookieTest < RedmineSaml::TestCase
  fixtures :users

  class RequestDouble
    def initialize(ssl:)
      @ssl = ssl
    end

    def ssl?
      @ssl
    end
  end

  # Records what would be written to the encrypted cookie jar.
  class CookieJarDouble
    attr_reader :written

    def initialize
      @written = {}
    end

    def encrypted
      self
    end

    def []=(name, options)
      # Rails mutates the options hash, so a copy is recorded.
      @written[name] = options.dup
    end
  end

  setup do
    RedmineSaml::SloTokenStore.register_action!
    @user = users :users_001
    @context = RedmineSaml::SloContext.active(
      user_id: @user.id,
      token: RedmineSaml::SloTokenStore.create_transaction(@user),
      name_id: @user.mail,
      session_index: '_session-index',
      settings: RedmineSaml.configured_saml
    )
  end

  test 'write_active still serializes the context and writes the active cookie' do
    jar = CookieJarDouble.new

    slo_cookie(jar).write_active @context

    options = jar.written.fetch RedmineSaml::SloCookie::ACTIVE_NAME
    assert_equal RedmineSaml::SloContext.dump(@context), options[:value]
    assert options[:secure]
    assert options[:httponly]
    assert_equal :none, options[:same_site]
    assert_equal RedmineSaml::LOGOUT_SERVICE_PATH, options[:path]
    assert_not options.key?(:expires)
  end

  test 'write_active and write_active_payload produce the same cookie' do
    context_jar = CookieJarDouble.new
    payload_jar = CookieJarDouble.new

    slo_cookie(context_jar).write_active @context
    slo_cookie(payload_jar).write_active_payload RedmineSaml::SloContext.dump(@context)

    assert_equal context_jar.written, payload_jar.written
  end

  test 'write_active_payload writes the given payload verbatim' do
    jar = CookieJarDouble.new

    slo_cookie(jar).write_active_payload 'already-serialized'

    assert_equal 'already-serialized',
                 jar.written.fetch(RedmineSaml::SloCookie::ACTIVE_NAME)[:value]
  end

  test 'both active writes stay a no-op without SSL' do
    context_jar = CookieJarDouble.new
    payload_jar = CookieJarDouble.new

    slo_cookie(context_jar, ssl: false).write_active @context
    slo_cookie(payload_jar, ssl: false).write_active_payload RedmineSaml::SloContext.dump(@context)

    assert_empty context_jar.written
    assert_empty payload_jar.written
  end

  test 'write_pending is unaffected by the active write split' do
    jar = CookieJarDouble.new
    pending = RedmineSaml::SloContext.pending(
      transaction_id: '_transaction-id',
      user_id: @user.id,
      token: RedmineSaml::SloTokenStore.create_transaction(@user),
      login: @user.login,
      settings: RedmineSaml.configured_saml
    )

    slo_cookie(jar).write_pending pending

    options = jar.written.fetch RedmineSaml::SloCookie::PENDING_NAME
    assert_equal RedmineSaml::SloContext.dump(pending), options[:value]
    assert options[:expires].present?
  end

  private

  def slo_cookie(jar, ssl: true)
    RedmineSaml::SloCookie.new request: RequestDouble.new(ssl: ssl), cookies: jar
  end
end
