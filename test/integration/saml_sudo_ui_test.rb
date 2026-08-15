# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

# Display texts of the SAML Sudo Mode confirmation prompt.
#
# The heading, the explanation and the button label can each be overridden by
# an optional plugin setting. While a setting is blank the prompt uses the
# translation of the current locale, so an installation that configures none of
# them keeps exactly the prompt it had before these settings existed, in every
# language. Nothing an administrator enters is ever treated as markup.
class SamlSudoUiTest < Redmine::IntegrationTest
  fixtures :users, :groups_users, :email_addresses, :user_preferences, :roles

  include RedmineSaml::TestHelper
  include Redmine::I18n

  CUSTOM_TITLE = 'Confirm with the company IdP'
  CUSTOM_TEXT = 'Your administrator requires an SSO confirmation for this action.'
  CUSTOM_BUTTON = 'Continue to the company IdP'

  # None of these may ever reach the browser as markup.
  HTML_TITLE = %(<script>alert("title")</script>)
  HTML_TEXT = %(<b onclick="alert('text')">bold</b>)
  HTML_BUTTON = %(<img src=x onerror="alert('button')">)

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
  # Unconfigured: the 1.2.0 prompt, unchanged
  # ---------------------------------------------------------------------------

  test 'shows the translated prompt while no display text is configured' do
    show_sudo_prompt

    assert_prompt title: l(:label_saml_sudo_reauth_required),
                  text: l(:text_saml_sudo_reauth_info),
                  button: l(:button_saml_sudo_reauth)
  end

  test 'shows the translated prompt in the modal while no display text is configured' do
    show_sudo_modal

    assert_modal_prompt title: l(:label_saml_sudo_reauth_required),
                        text: l(:text_saml_sudo_reauth_info),
                        button: l(:button_saml_sudo_reauth)
  end

  test 'treats blank display texts as unconfigured' do
    change_saml_settings saml_sudo_reauth_title: '',
                         saml_sudo_reauth_text: '',
                         saml_sudo_reauth_button_label: ''
    show_sudo_prompt

    assert_prompt title: l(:label_saml_sudo_reauth_required),
                  text: l(:text_saml_sudo_reauth_info),
                  button: l(:button_saml_sudo_reauth)
  end

  test 'treats whitespace only display texts as unconfigured' do
    change_saml_settings saml_sudo_reauth_title: '   ',
                         saml_sudo_reauth_text: "\n\t ",
                         saml_sudo_reauth_button_label: "\t"
    show_sudo_prompt

    assert_prompt title: l(:label_saml_sudo_reauth_required),
                  text: l(:text_saml_sudo_reauth_info),
                  button: l(:button_saml_sudo_reauth)
  end

  # The unconfigured prompt has to follow the locale, which is why the current
  # English wording is not copied into the settings as a default value.
  test 'keeps the translated prompt for a locale that is not English' do
    with_locale 'de' do
      show_sudo_prompt

      assert_prompt title: ::I18n.t(:label_saml_sudo_reauth_required, locale: :de),
                    text: ::I18n.t(:text_saml_sudo_reauth_info, locale: :de),
                    button: ::I18n.t(:button_saml_sudo_reauth, locale: :de)
      assert_not_includes response.body, ::I18n.t(:label_saml_sudo_reauth_required, locale: :en)
    end
  end

  test 'overrides the translated prompt of a locale that is not English' do
    configure_custom_texts
    with_locale 'de' do
      show_sudo_prompt

      assert_prompt title: CUSTOM_TITLE, text: CUSTOM_TEXT, button: CUSTOM_BUTTON
      assert_not_includes response.body, ::I18n.t(:label_saml_sudo_reauth_required, locale: :de)
    end
  end

  # ---------------------------------------------------------------------------
  # Each setting overrides exactly one text
  # ---------------------------------------------------------------------------

  test 'overrides only the heading when only the heading is configured' do
    change_saml_settings saml_sudo_reauth_title: CUSTOM_TITLE
    show_sudo_prompt

    assert_prompt title: CUSTOM_TITLE,
                  text: l(:text_saml_sudo_reauth_info),
                  button: l(:button_saml_sudo_reauth)
    assert_select 'h2', text: l(:label_saml_sudo_reauth_required), count: 0
  end

  test 'overrides only the explanation when only the explanation is configured' do
    change_saml_settings saml_sudo_reauth_text: CUSTOM_TEXT
    show_sudo_prompt

    assert_prompt title: l(:label_saml_sudo_reauth_required),
                  text: CUSTOM_TEXT,
                  button: l(:button_saml_sudo_reauth)
    assert_not_includes response.body, l(:text_saml_sudo_reauth_info)
  end

  test 'overrides only the button label when only the button label is configured' do
    change_saml_settings saml_sudo_reauth_button_label: CUSTOM_BUTTON
    show_sudo_prompt

    assert_prompt title: l(:label_saml_sudo_reauth_required),
                  text: l(:text_saml_sudo_reauth_info),
                  button: CUSTOM_BUTTON
    assert_select 'form#saml-sudo-reauth-form button', text: l(:button_saml_sudo_reauth), count: 0
  end

  test 'overrides all three texts when all three are configured' do
    configure_custom_texts
    show_sudo_prompt

    assert_prompt title: CUSTOM_TITLE, text: CUSTOM_TEXT, button: CUSTOM_BUTTON
    assert_not_includes response.body, l(:label_saml_sudo_reauth_required)
    assert_not_includes response.body, l(:text_saml_sudo_reauth_info)
    assert_not_includes response.body, l(:button_saml_sudo_reauth)
  end

  test 'overrides all three texts in the modal as well' do
    configure_custom_texts
    show_sudo_modal

    assert_modal_prompt title: CUSTOM_TITLE, text: CUSTOM_TEXT, button: CUSTOM_BUTTON
    assert_not_includes response.body, l(:label_saml_sudo_reauth_required)
    assert_not_includes response.body, l(:button_saml_sudo_reauth)
  end

  # ---------------------------------------------------------------------------
  # Plain text only
  # ---------------------------------------------------------------------------

  test 'renders HTML in the configured texts as text instead of markup' do
    change_saml_settings saml_sudo_reauth_title: HTML_TITLE,
                         saml_sudo_reauth_text: HTML_TEXT,
                         saml_sudo_reauth_button_label: HTML_BUTTON
    show_sudo_prompt

    # assert_select compares the decoded text of the element, so this passes
    # only while the value is content and not markup.
    assert_prompt title: HTML_TITLE, text: HTML_TEXT, button: HTML_BUTTON
    assert_select 'h2 script', 0
    assert_select 'p.nodata b', 0
    assert_select 'form#saml-sudo-reauth-form img', 0
    assert_not_includes response.body, HTML_TITLE
    assert_not_includes response.body, HTML_TEXT
    assert_not_includes response.body, HTML_BUTTON
    assert_includes response.body, '&lt;script&gt;'
  end

  test 'renders HTML in the configured texts as text in the modal as well' do
    change_saml_settings saml_sudo_reauth_title: HTML_TITLE,
                         saml_sudo_reauth_text: HTML_TEXT,
                         saml_sudo_reauth_button_label: HTML_BUTTON
    show_sudo_modal

    assert_not_includes response.body, HTML_TITLE
    assert_not_includes response.body, HTML_TEXT
    assert_not_includes response.body, HTML_BUTTON
    assert_includes response.body, '&lt;script&gt;'
  end

  # ---------------------------------------------------------------------------
  # Saved through the plugin settings form
  # ---------------------------------------------------------------------------

  test 'shows the texts that were saved through the plugin settings form' do
    saml_login

    # Still within the Sudo Mode timeout of the login, so the settings form is
    # reached without a confirmation.
    post '/settings/plugin/redmine_saml',
         params: { settings: { saml_enabled: '1',
                               saml_login_label: '',
                               replace_redmine_login: '0',
                               onthefly_creation: '0',
                               saml_sudo_reauth_title: CUSTOM_TITLE,
                               saml_sudo_reauth_text: CUSTOM_TEXT,
                               saml_sudo_reauth_button_label: CUSTOM_BUTTON } }
    assert_redirected_to '/settings/plugin/redmine_saml'

    expire_sudo_mode!
    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_prompt title: CUSTOM_TITLE, text: CUSTOM_TEXT, button: CUSTOM_BUTTON
  end

  # ---------------------------------------------------------------------------
  # Everything outside the SAML Sudo prompt is untouched
  # ---------------------------------------------------------------------------

  test 'never applies the configured texts to the local Redmine password prompt' do
    configure_custom_texts
    log_user 'admin', 'admin'
    expire_sudo_mode!

    post '/roles', params: { role: { name: 'a new role' } }

    assert_response :success
    assert_select 'input[name=sudo_password]'
    assert_select 'form#saml-sudo-reauth-form', 0
    assert_no_custom_text
  end

  test 'never renders a prompt at all while Redmine Sudo Mode is off' do
    configure_custom_texts
    with_sudo_mode_disabled do
      saml_login
      expire_sudo_mode!

      assert_difference 'Role.count' do
        post '/roles',
             params: { role: { name: 'a new role',
                               issues_visibility: 'all',
                               assignable: '1',
                               permissions: %w[view_calendar] } }
      end
      assert_redirected_to '/roles'
      assert_select 'form#saml-sudo-reauth-form', 0
      assert_no_custom_text
    end
  end

  test 'never applies the configured texts to the SAML login button' do
    configure_custom_texts

    get '/login'

    assert_response :success
    assert_select '#saml-login button', text: l(:saml_login_label)
    assert_no_custom_text
  end

  private

  def configure_custom_texts
    change_saml_settings saml_sudo_reauth_title: CUSTOM_TITLE,
                         saml_sudo_reauth_text: CUSTOM_TEXT,
                         saml_sudo_reauth_button_label: CUSTOM_BUTTON
  end

  # The whole page prompt, as a normal browser request receives it.
  def show_sudo_prompt
    saml_login
    expire_sudo_mode!
    post '/roles',
         params: { role: { name: 'a new role' } },
         headers: { 'HTTP_REFERER' => '/roles/new' }
    assert_response :success
    assert_select 'form#saml-sudo-reauth-form'
  end

  # The modal prompt, as an XHR receives it: JavaScript that injects the
  # rendered partial, so it is asserted against the response body.
  def show_sudo_modal
    saml_login
    expire_sudo_mode!
    post '/roles', params: { role: { name: 'a new role' } }, xhr: true
    assert_response :success
    assert_includes response.body, 'saml-sudo-reauth-form'
  end

  def assert_prompt(title:, text:, button:)
    assert_select 'h2', text: title
    assert_select 'p.nodata', text: text
    assert_select 'form#saml-sudo-reauth-form button', text: button
  end

  def assert_modal_prompt(title:, text:, button:)
    [title, text, button].each do |value|
      assert_includes response.body, escape_javascript(ERB::Util.html_escape(value))
    end
  end

  def assert_no_custom_text
    [CUSTOM_TITLE, CUSTOM_TEXT, CUSTOM_BUTTON].each do |value|
      assert_not_includes response.body, value
    end
  end

  def escape_javascript(value)
    ActionView::Base.empty.escape_javascript value
  end

  # Redmine picks the locale from the signed-in user first, so both sources are
  # switched here.
  def with_locale(locale)
    user = users :users_001
    original_default_language = Setting.default_language
    original_user_language = user.language
    Setting.default_language = locale
    user.update_column :language, locale
    yield
  ensure
    Setting.default_language = original_default_language
    user.update_column :language, original_user_language
  end

  # Redmine reads sudo_mode once at boot, so the setup block turns it on for
  # this whole test case and this turns it off again for a single test.
  def with_sudo_mode_disabled
    Redmine::SudoMode.unstub :enabled?
    Redmine::SudoMode.stubs(:enabled?).returns false
    yield
  end

  def saml_login
    post RedmineSaml::CALLBACK_PATH
    assert_redirected_to '/my/page'
    assert_equal users(:users_001).id, session[:user_id]
    assert session[:logged_in_with_saml]
  end

  # Sudo Mode is active right after signing in; let it expire.
  def expire_sudo_mode!
    travel_to 20.minutes.from_now
  end
end
