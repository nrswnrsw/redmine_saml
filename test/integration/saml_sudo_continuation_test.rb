# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'uri'

# Keeping the input of the request that triggered a SAML Sudo Mode confirmation
# across the IdP round trip.
#
# The whole browser side is simulated here: the opaque continuation is read out
# of the confirmation page exactly where the script would store it, carried by
# hand as sessionStorage would carry it, and handed back through the form the
# resume page actually rendered. Nothing about the resume URL or that form is
# rebuilt by this test, so the round trip really is the one a browser makes.
#
# What must hold throughout is that a successful SAML confirmation never
# changes anything by itself, and that only the form the user submits does.
class SamlSudoContinuationTest < Redmine::IntegrationTest
  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  include RedmineSaml::TestHelper

  ROLE_PARAMS = { name: 'a new role',
                  issues_visibility: 'all',
                  assignable: '1',
                  permissions: %w[view_calendar] }.freeze

  setup do
    prepare_tests
    Redmine::SudoMode.stubs(:enabled?).returns(true)
    @original_test_mode = OmniAuth.config.test_mode
    @original_mock_auth = OmniAuth.config.mock_auth[:saml]
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:saml] = { 'saml_login' => 'admin' }
  end

  teardown do
    travel_back
    OmniAuth.config.test_mode = @original_test_mode
    OmniAuth.config.mock_auth[:saml] = @original_mock_auth
  end

  # ---------------------------------------------------------------------------
  # The input survives the IdP round trip
  # ---------------------------------------------------------------------------

  test 'keeps the input of the request that triggered the confirmation' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    assert stash[:value].present?, 'the confirmation page must carry a continuation'
    assert RedmineSaml::SudoContinuation.key?(stash[:key])
    assert_not_includes stash[:value], 'a new role', 'the input must not be readable in the page'
  end

  # The round trip as the browser makes it: the redirect the callback produced
  # is followed as it stands, and the form that page rendered is what carries
  # the continuation back.
  test 'restores the original fields by following the real callback redirect' do
    role_count = Role.count
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    confirm_with_idp stash
    assert_response :redirect
    location = URI.parse response.location
    query = Rack::Utils.parse_query location.query.to_s

    assert_equal '/saml/sudo_resume', location.path
    assert_equal stash[:key], query['key'],
                 'the continuation key has to survive the whole SAML Sudo transaction'
    assert_equal '/roles/new', query['back_url'],
                 'the validated back URL of the original request has to survive it too'

    follow_redirect!

    assert_response :success
    assert_select 'form#saml-sudo-resume-form'
    assert_select 'form#saml-sudo-resume-form input[name=?][value=?]', 'key', stash[:key]
    assert_select 'form#saml-sudo-resume-form input[name=?][value=?]', 'back_url', '/roles/new'

    restore_continuation stash[:value]

    assert_response :success
    assert_select 'form#saml-sudo-continue-form[action=?]', '/roles'
    assert_select 'input[name=?][value=?]', '_method', 'POST'
    assert_select 'input[name=?][value=?]', 'role[name]', 'a new role'
    assert_select 'input[name=?][value=?]', 'role[permissions][]', 'view_calendar'
    assert_equal role_count, Role.count, 'restoring the input must not change anything'
  end

  test 'performs the original request only when the user submits it' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    open_resume_page confirm_with_idp(stash)
    restore_continuation stash[:value]

    assert_difference 'Role.count', 1 do
      submit_continue_form
    end
    assert_redirected_to '/roles'
    assert Role.find_by(name: 'a new role')
  end

  # The resumed request is replayed with its original method through _method,
  # exactly as Redmine's own Sudo Mode prompt does. RolesController#update is
  # identical on Redmine 6.0, 6.1 and 7.0 and touches one fixture row.
  test 'resumes a PATCH request as a PATCH request' do
    role = roles :roles_001
    saml_login
    expire_sudo_mode!

    patch "/roles/#{role.id}",
          params: { role: { name: 'a renamed role' } },
          headers: { 'HTTP_REFERER' => "/roles/#{role.id}/edit" }
    assert_response :success
    stash = stashed_continuation
    assert stash[:value].present?, 'a PATCH must be continued as well'

    open_resume_page confirm_with_idp(stash, back_url: "/roles/#{role.id}/edit")
    restore_continuation stash[:value]

    assert_response :success
    assert_select 'form#saml-sudo-continue-form[action=?]', "/roles/#{role.id}"
    assert_select 'input[name=?][value=?]', '_method', 'PATCH'
    assert_equal 'Manager', role.reload.name, 'restoring the input must not change anything'

    submit_continue_form

    assert_redirected_to '/roles'
    assert_equal 'a renamed role', role.reload.name,
                 'the resumed request has to reach the action as a PATCH'
  end

  # ---------------------------------------------------------------------------
  # A successful confirmation is never on its own a reason to change anything
  # ---------------------------------------------------------------------------

  test 'never performs the original request from the SAML callback' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    assert_no_difference 'Role.count' do
      open_resume_page confirm_with_idp(stash)
      restore_continuation stash[:value]
    end
    assert_nil Role.find_by(name: 'a new role')
  end

  test 'never performs the original request when the callback is replayed' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    relay_state = relay_state_of confirm_with_idp(stash)

    assert_no_difference 'Role.count' do
      post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }
      post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state }
    end
    assert_nil Role.find_by(name: 'a new role')
    assert_equal users(:users_001).id, session[:user_id]
  end

  test 'never performs the original request when the resume page is reloaded' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    location = confirm_with_idp stash

    assert_no_difference 'Role.count' do
      3.times do
        open_resume_page location
        restore_continuation stash[:value]
      end
    end
  end

  # ---------------------------------------------------------------------------
  # The resumed request is an ordinary request
  # ---------------------------------------------------------------------------

  test 'lets Redmine ask for confirmation again when the sudo timestamp lapsed' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    open_resume_page confirm_with_idp(stash)
    restore_continuation stash[:value]

    # The identity was confirmed, but the confirmation lapses again before the
    # user gets around to submitting the restored form.
    expire_sudo_mode!

    assert_no_difference 'Role.count' do
      submit_continue_form
    end
    assert_response :success
    assert_select 'form#saml-sudo-reauth-form', 1, 'Redmine has to ask for confirmation again'
    # The input is not lost by that second confirmation either.
    assert stashed_continuation[:value].present?
  end

  # The resume pages must never be cached: they carry restored user input and
  # are reached with the browser back button after a redirect.
  test 'never lets a browser cache the resume or the restored form' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    open_resume_page confirm_with_idp(stash)
    assert_includes response.headers['Cache-Control'], 'no-store',
                    'the resume page must not be cached'

    restore_continuation stash[:value]

    assert_response :success
    assert_select 'form#saml-sudo-continue-form'
    assert_includes response.headers['Cache-Control'], 'no-store',
                    'the restored input must not be cached'
  end

  test 'ships the restore script with every page of the flow' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    assert_select 'script[src*=?]', 'saml_sudo_continuation', 1

    open_resume_page confirm_with_idp(stash)
    assert_select 'script[src*=?]', 'saml_sudo_continuation', 1

    restore_continuation stash[:value]
    assert_select 'script[src*=?]', 'saml_sudo_continuation', 1
  end

  test 'gives the restored form a fresh CSRF token and never the original one' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    location = confirm_with_idp stash

    with_forgery_protection do
      open_resume_page location
      assert css_select('form#saml-sudo-resume-form input[name=authenticity_token]').first,
             'the resume form has to be CSRF protected'

      restore_continuation stash[:value]

      assert_response :success
      assert_select 'form#saml-sudo-continue-form input[name=?]', 'authenticity_token', 1
      assert css_select('form#saml-sudo-continue-form input[name=authenticity_token]').first['value'].present?
    end
  end

  test 'requires a CSRF token to restore a continuation' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    confirm_with_idp stash

    with_forgery_protection do
      post '/saml/sudo_resume', params: { continuation: stash[:value], key: stash[:key], back_url: '/roles/new' }

      assert_response :unprocessable_content
      assert_select 'form#saml-sudo-continue-form', 0
    end
  end

  # ---------------------------------------------------------------------------
  # An untrusted continuation is rejected
  # ---------------------------------------------------------------------------

  test 'rejects a continuation the browser modified' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    open_resume_page confirm_with_idp(stash)

    assert_no_difference 'Role.count' do
      restore_continuation "#{stash[:value]}x"
    end
    assert_resume_unavailable
  end

  test 'rejects a continuation once its validity passed' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    open_resume_page confirm_with_idp(stash)

    travel_to RedmineSaml::SudoContinuation::VALIDITY.from_now + 1.minute
    restore_continuation stash[:value]

    assert_resume_unavailable
  end

  test 'rejects a continuation of another user' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    other_user = open_session
    OmniAuth.config.mock_auth[:saml] = { 'saml_login' => users(:users_002).login }
    other_user.post RedmineSaml::CALLBACK_PATH
    assert_equal users(:users_002).id, other_user.session[:user_id]

    assert_no_difference 'Role.count' do
      other_user.post '/saml/sudo_resume',
                      params: { continuation: stash[:value], key: stash[:key], back_url: '/roles/new' }
    end
    assert_resume_unavailable other_user.response
  end

  test 'rejects a continuation of another login session of the same user' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    other_tab = open_session
    other_tab.post RedmineSaml::CALLBACK_PATH
    assert_equal users(:users_001).id, other_tab.session[:user_id]

    assert_no_difference 'Role.count' do
      other_tab.post '/saml/sudo_resume',
                     params: { continuation: stash[:value], key: stash[:key], back_url: '/roles/new' }
    end
    assert_resume_unavailable other_tab.response
  end

  test 'rejects a continuation after the login session was replaced' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    location = confirm_with_idp stash

    # A normal SAML login resets the session, so its per session secret is gone.
    post RedmineSaml::CALLBACK_PATH
    assert_redirected_to '/my/page'

    open_resume_page location
    restore_continuation stash[:value]

    assert_resume_unavailable
  end

  # ---------------------------------------------------------------------------
  # Failure modes
  # ---------------------------------------------------------------------------

  test 'offers a way back when the browser kept no continuation' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form

    # sessionStorage unavailable or empty: the page submits nothing.
    open_resume_page confirm_with_idp(stash)
    assert_select 'form#saml-sudo-resume-form'
    assert_select 'a[href=?]', '/roles/new'

    restore_continuation ''

    assert_resume_unavailable
  end

  test 'keeps the login session when the SAML callback fails' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    post '/saml/sudo_reauth', params: { back_url: stash[:back_url] }
    assert_response :redirect

    # A Response that answers no transaction of this session.
    post RedmineSaml::CALLBACK_PATH,
         params: { RelayState: RedmineSaml::SudoReauth.relay_state('deadbeefdeadbeefdeadbeefdeadbeef') }

    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
    assert_nil Role.find_by(name: 'a new role')
  end

  test 'never leaves a resume page that submits itself in a loop' do
    saml_login
    expire_sudo_mode!
    stash = submit_protected_form
    open_resume_page confirm_with_idp(stash)

    restore_continuation 'broken'

    assert_resume_unavailable
    assert_select 'form#saml-sudo-resume-form', 0, 'the rejected page must not carry the restore form again'
    assert_select 'script[src*=?]', 'saml_sudo_continuation', 0
  end

  # ---------------------------------------------------------------------------
  # Nothing outside this flow changes
  # ---------------------------------------------------------------------------

  test 'gives each confirmation its own browser storage key' do
    saml_login
    expire_sudo_mode!

    first = submit_protected_form
    second = submit_protected_form

    assert_not_equal first[:key], second[:key],
                     'two drafts must never share a browser storage key'
    assert_not_equal first[:value], second[:value]
  end

  test 'keeps the local Redmine password prompt exactly as it was' do
    log_user 'admin', 'admin'
    expire_sudo_mode!

    post '/roles', params: { role: ROLE_PARAMS }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
    # Redmine's own prompt keeps the input in hidden fields of the same page.
    assert_select 'input[name=?][value=?]', 'role[name]', 'a new role'
    assert_select 'form[data-saml-sudo-stash]', 0
    assert_nil session[RedmineSaml::SudoContinuation::SESSION_KEY]
  end

  test 'never stores continuation state for a normal SAML login' do
    saml_login

    assert_nil session[RedmineSaml::SudoContinuation::SESSION_KEY]

    get '/logout'
    post '/logout'

    assert_nil session[RedmineSaml::SudoContinuation::SESSION_KEY]
  end

  test 'stores continuation state only once a continuation is created' do
    saml_login
    expire_sudo_mode!

    # A GET has nothing to continue.
    get '/settings/plugin/redmine_saml', headers: { 'HTTP_REFERER' => '/admin' }
    assert_select 'form#saml-sudo-reauth-form'
    assert_nil session[RedmineSaml::SudoContinuation::SESSION_KEY]

    submit_protected_form

    assert session[RedmineSaml::SudoContinuation::SESSION_KEY].present?
  end

  test 'refuses the resume page without an active SAML session' do
    log_user 'admin', 'admin'

    get '/saml/sudo_resume'

    assert_response :forbidden
  end

  private

  # What the browser script would put into sessionStorage, read off the
  # confirmation page that is currently rendered.
  def stashed_continuation
    form = css_select('form#saml-sudo-reauth-form').first
    assert form, 'the SAML confirmation page must be shown'

    { value: form['data-saml-sudo-stash'],
      key: form['data-saml-sudo-stash-key'],
      back_url: css_select('form#saml-sudo-reauth-form input[name=back_url]').first['value'] }
  end

  # Submits the protected form whose Sudo Mode window has lapsed.
  def submit_protected_form
    post '/roles', params: { role: ROLE_PARAMS }, headers: { 'HTTP_REFERER' => '/roles/new' }
    assert_response :success
    stashed_continuation
  end

  # The IdP round trip. Returns the URL the callback actually redirected to, so
  # that no caller has to rebuild it, and asserts that the continuation key and
  # the validated back URL survived the whole transaction.
  def confirm_with_idp(stash, back_url: '/roles/new')
    post '/saml/sudo_reauth', params: { back_url: stash[:back_url] }
    assert_response :redirect
    post RedmineSaml::CALLBACK_PATH, params: { RelayState: relay_state_of(response.location) }
    assert_response :redirect

    location = URI.parse response.location
    query = Rack::Utils.parse_query location.query.to_s
    assert_equal '/saml/sudo_resume', location.path
    assert_equal stash[:key], query['key'],
                 'the continuation key has to survive the whole SAML Sudo transaction'
    assert_equal back_url, query['back_url'],
                 'the validated back URL of the original request has to survive it too'

    response.location
  end

  # Follows the redirect the callback produced, as it stands.
  def open_resume_page(location)
    get location
    assert_response :success
    assert_select 'form#saml-sudo-resume-form'
  end

  # What the restore script does: fill the hidden field of the resume form that
  # is on screen and submit that form as it was rendered.
  def restore_continuation(value)
    form = css_select('form#saml-sudo-resume-form').first
    assert form, 'the resume form must be rendered'
    fields = css_select('form#saml-sudo-resume-form input[type=hidden]')
             .to_h { |input| [input['name'], input['value']] }
    fields['continuation'] = value
    post form['action'], params: fields
  end

  # What the user does: submit the restored form as an ordinary request.
  def submit_continue_form
    form = css_select('form#saml-sudo-continue-form').first
    assert form, 'the restored form must be shown'
    fields = css_select('form#saml-sudo-continue-form input[type=hidden]')
             .to_h { |input| [input['name'], input['value']] }
    post form['action'], params: fields
  end

  def assert_resume_unavailable(actual = response)
    assert_equal 200, actual.status
    assert_includes actual.body, ERB::Util.html_escape(I18n.t(:text_saml_sudo_resume_unavailable))
    assert_select 'form#saml-sudo-continue-form', 0
  end

  def saml_login
    post RedmineSaml::CALLBACK_PATH
    assert_redirected_to '/my/page'
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  def expire_sudo_mode!
    travel_to 20.minutes.from_now
  end

  def relay_state_of(location)
    Rack::Utils.parse_query(URI.parse(location.to_s).query.to_s)['RelayState']
  end
end
