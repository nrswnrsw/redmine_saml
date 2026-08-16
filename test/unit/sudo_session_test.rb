# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

# The Redmine login session identity SAML Sudo re-authentication is scoped to.
#
# Everything derived here has to be a pure function of session[:tk]: that is
# what lets two genuinely concurrent tabs of one login session agree without
# writing anything to a session cookie neither of them can arbitrate.
class SudoSessionTest < RedmineSaml::TestCase
  LOCK_LENGTH = RedmineSaml::SudoTokenStore::LOCK_VALUE_LENGTH

  test 'reads the Redmine session token whichever way the session is keyed' do
    assert_equal 'tk-a', RedmineSaml::SudoSession.token(tk: 'tk-a')
    assert_equal 'tk-a', RedmineSaml::SudoSession.token('tk' => 'tk-a')
    assert RedmineSaml::SudoSession.known?(tk: 'tk-a')
  end

  test 'has no identity without a Redmine session token' do
    [{}, { tk: nil }, { tk: '' }, nil].each do |session|
      assert_nil RedmineSaml::SudoSession.token(session), session.inspect
      assert_not RedmineSaml::SudoSession.known?(session), session.inspect
      assert_nil RedmineSaml::SudoSession.lock_value(session, length: LOCK_LENGTH), session.inspect
      assert_nil RedmineSaml::SudoSession.continuation_secret(session), session.inspect
    end
  end

  # The property the whole single-flight and continuation binding rests on.
  test 'derives the same values for every request of one login session' do
    session = { tk: 'tk-a' }
    other = { tk: 'tk-a' }

    assert_equal RedmineSaml::SudoSession.lock_value(session, length: LOCK_LENGTH),
                 RedmineSaml::SudoSession.lock_value(other, length: LOCK_LENGTH)
    assert_equal RedmineSaml::SudoSession.continuation_secret(session),
                 RedmineSaml::SudoSession.continuation_secret(other)
  end

  test 'derives different values for different login sessions' do
    a = { tk: 'tk-a' }
    b = { tk: 'tk-b' }

    assert_not_equal RedmineSaml::SudoSession.lock_value(a, length: LOCK_LENGTH),
                     RedmineSaml::SudoSession.lock_value(b, length: LOCK_LENGTH)
    assert_not_equal RedmineSaml::SudoSession.continuation_secret(a),
                     RedmineSaml::SudoSession.continuation_secret(b)
  end

  test 'separates the lock value from the continuation secret' do
    session = { tk: 'tk-a' }

    assert_not_equal RedmineSaml::SudoSession.lock_value(session, length: 64),
                     RedmineSaml::SudoSession.continuation_secret(session)
  end

  test 'never exposes the raw Redmine session token in a derived value' do
    token = 'a-very-recognisable-session-token'
    session = { tk: token }

    [RedmineSaml::SudoSession.lock_value(session, length: LOCK_LENGTH),
     RedmineSaml::SudoSession.continuation_secret(session)].each do |derived|
      assert_not_includes derived, token
      assert_match(/\A[0-9a-f]+\z/, derived)
    end
  end

  test 'fits the lock value into the tokens value column' do
    value = RedmineSaml::SudoSession.lock_value({ tk: 'tk-a' }, length: LOCK_LENGTH)

    assert_equal LOCK_LENGTH, value.length
    assert_operator value.length, :<=, 40
  end
end
