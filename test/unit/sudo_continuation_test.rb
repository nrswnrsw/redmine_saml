# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__
require 'tempfile'

# The seal around the input of the request that triggered a SAML Sudo Mode
# confirmation. Everything the browser hands back is untrusted, so every check
# here has to fail closed rather than fall back to something usable.
class SudoContinuationTest < RedmineSaml::TestCase
  SECRET = 'a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5'
  OTHER_SECRET = 'ffffffffffffffffffffffffffffffff'
  USER_ID = 2
  FIELDS = { 'role' => { 'name' => 'a new role', 'permissions' => %w[view_calendar] } }.freeze

  def dump(**overrides)
    RedmineSaml::SudoContinuation.dump user_id: USER_ID,
                                       session_secret: SECRET,
                                       request_method: 'POST',
                                       path: '/roles',
                                       fields: FIELDS,
                                       **overrides
  end

  def load_dumped(serialized, **overrides)
    RedmineSaml::SudoContinuation.load serialized, user_id: USER_ID, session_secret: SECRET, **overrides
  end

  # ---------------------------------------------------------------------------
  # Round trip
  # ---------------------------------------------------------------------------

  test 'restores the original method, path and fields' do
    payload = load_dumped dump

    assert_equal 'POST', payload['request_method']
    assert_equal '/roles', payload['path']
    assert_equal FIELDS, payload['fields']
    assert_equal USER_ID, payload['user_id']
  end

  test 'keeps the input out of the sealed value' do
    serialized = dump

    assert_not_includes serialized, 'a new role'
    assert_not_includes serialized, 'view_calendar'
    assert_not_includes serialized, '/roles'
    assert_not_includes serialized, SECRET
  end

  # ---------------------------------------------------------------------------
  # Tamper resistance
  # ---------------------------------------------------------------------------

  test 'rejects a modified continuation' do
    serialized = dump

    assert_nil load_dumped("#{serialized}x")
    assert_nil load_dumped(serialized.sub(/\A./, 'A'))
    assert_nil load_dumped('not-a-continuation')
    assert_nil load_dumped('')
    assert_nil load_dumped(nil)
  end

  test 'rejects a continuation sealed for another purpose' do
    key = Rails.application.key_generator.generate_key 'redmine_saml/other',
                                                       ActiveSupport::MessageEncryptor.key_len
    foreign = ActiveSupport::MessageEncryptor.new(key, serializer: JSON)
                                             .encrypt_and_sign({ 'version' => 1,
                                                                 'user_id' => USER_ID,
                                                                 'request_method' => 'POST',
                                                                 'path' => '/roles',
                                                                 'fields' => FIELDS },
                                                               purpose: 'redmine_saml/sudo_continuation')

    assert_nil load_dumped(foreign)
  end

  # ---------------------------------------------------------------------------
  # Expiry
  # ---------------------------------------------------------------------------

  test 'rejects a continuation once its validity passed' do
    serialized = dump

    travel_to RedmineSaml::SudoContinuation::VALIDITY.from_now - 10.seconds do
      assert load_dumped(serialized), 'must still be usable inside the validity window'
    end
    travel_to RedmineSaml::SudoContinuation::VALIDITY.from_now + 10.seconds do
      assert_nil load_dumped(serialized)
    end
  end

  # ---------------------------------------------------------------------------
  # User and session binding
  # ---------------------------------------------------------------------------

  test 'rejects a continuation of another user' do
    assert_nil load_dumped(dump, user_id: USER_ID + 1)
  end

  test 'rejects a continuation of another login session' do
    assert_nil load_dumped(dump, session_secret: OTHER_SECRET)
  end

  test 'rejects a continuation when the session secret is gone' do
    serialized = dump

    assert_nil load_dumped(serialized, session_secret: nil)
    assert_nil load_dumped(serialized, session_secret: '')
  end

  test 'refuses to seal a continuation without a session secret' do
    assert_nil dump(session_secret: nil)
    assert_nil dump(session_secret: '')
  end

  # ---------------------------------------------------------------------------
  # What may be continued at all
  # ---------------------------------------------------------------------------

  test 'only continues the request methods Redmine itself resubmits' do
    %w[POST PUT PATCH DELETE].each do |method|
      assert dump(request_method: method), "#{method} must be resumable"
    end
    %w[GET HEAD OPTIONS].each do |method|
      assert_nil dump(request_method: method), "#{method} must not be resumable"
    end
  end

  test 'refuses a path that is not a local Redmine path' do
    ['https://evil.test/roles', '//evil.test/roles', '/../secret', 'roles', '', nil, "/roles\n/x"].each do |path|
      assert_nil dump(path: path), "#{path.inspect} must not be sealed"
    end
  end

  test 'refuses to seal without fields' do
    assert_nil dump(fields: {})
    assert_nil dump(fields: nil)
  end

  # ---------------------------------------------------------------------------
  # Field selection
  # ---------------------------------------------------------------------------

  test 'keeps the fields Redmine selected as plain data' do
    fields = RedmineSaml::SudoContinuation.serializable_fields(
      ActionController::Parameters.new(role: { name: 'a new role', assignable: '1', permissions: %w[a b] })
    )

    assert_equal({ 'role' => { 'name' => 'a new role', 'assignable' => '1', 'permissions' => %w[a b] } }, fields)
  end

  test 'never carries framework parameters back into the resumed request' do
    fields = RedmineSaml::SudoContinuation.serializable_fields(
      ActionController::Parameters.new(role: { name: 'a new role' },
                                       authenticity_token: 'stale-token',
                                       _method: 'delete',
                                       utf8: '✓',
                                       sudo_password: 'secret',
                                       controller: 'roles',
                                       action: 'create')
    )

    assert_equal({ 'role' => { 'name' => 'a new role' } }, fields)
  end

  test 'refuses a raw uploaded file instead of serialising a placeholder' do
    Tempfile.create 'redmine_saml' do |tempfile|
      upload = ActionDispatch::Http::UploadedFile.new filename: 'x.txt',
                                                      type: 'text/plain',
                                                      tempfile: tempfile
      fields = RedmineSaml::SudoContinuation.serializable_fields(
        ActionController::Parameters.new(attachments: { 'dummy' => { 'file' => upload } })
      )

      assert_nil fields, 'a raw upload must stop the continuation instead of being stringified'
    end
  end

  test 'continues the attachment tokens of the normal Redmine upload flow' do
    fields = RedmineSaml::SudoContinuation.serializable_fields(
      ActionController::Parameters.new(issue: { subject: 'x' },
                                       attachments: { '1' => { 'token' => '7.abcdef', 'description' => 'd' } })
    )

    assert_equal '7.abcdef', fields.dig('attachments', '1', 'token')
  end

  test 'refuses fields that are larger than a browser should be asked to keep' do
    oversized = { 'issue' => { 'description' => 'x' * (RedmineSaml::SudoContinuation::MAX_FIELDS_BYTES + 1) } }

    assert_nil RedmineSaml::SudoContinuation.serializable_fields(ActionController::Parameters.new(oversized))
  end

  test 'refuses fields nested deeper than the depth limit' do
    deep = {}
    cursor = deep
    (RedmineSaml::SudoContinuation::MAX_FIELD_DEPTH + 2).times do |i|
      cursor["l#{i}"] = {}
      cursor = cursor["l#{i}"]
    end

    assert_nil RedmineSaml::SudoContinuation.serializable_fields(ActionController::Parameters.new(deep))
  end

  test 'has no fields to continue for an empty selection' do
    assert_nil RedmineSaml::SudoContinuation.serializable_fields(ActionController::Parameters.new)
    assert_nil RedmineSaml::SudoContinuation.serializable_fields(nil)
  end

  # ---------------------------------------------------------------------------
  # Storage key
  # ---------------------------------------------------------------------------

  test 'generates a distinct storage key per continuation' do
    keys = Array.new(50) { RedmineSaml::SudoContinuation.generate_key }

    assert_equal keys.size, keys.uniq.size, 'two continuations must never share a browser storage key'
    keys.each { |key| assert RedmineSaml::SudoContinuation.key?(key) }
  end

  test 'only accepts a storage key of the generated shape' do
    ['', nil, 'zz', '../etc', "#{'a' * 32}x", '<script>'].each do |value|
      assert_not RedmineSaml::SudoContinuation.key?(value), "#{value.inspect} must not pass as a storage key"
    end
  end
end
