# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class UserTest < RedmineSaml::TestCase
  setup do
    prepare_tests
  end

  context 'User#find_or_create_from_omniauth' do
    should 'find created user' do
      login_name = 'mylogin'
      u = User.new firstname: 'name',
                   lastname: 'last',
                   mail: 'mail@example.net',
                   login: login_name,
                   admin: false

      assert_save u
      assert_not_nil User.find_or_create_from_omniauth(saml_login: login_name)
    end

    context 'onthefly_creation? disabled' do
      setup do
        change_saml_settings onthefly_creation: 0
      end

      should 'return nil when user not exists' do
        assert_nil User.find_or_create_from_omniauth(saml_login: 'not_existent')
      end
    end

    context 'onthefly_creation? enabled' do
      setup do
        change_saml_settings onthefly_creation: 1
      end

      should 'return created user' do
        new = User.find_or_create_from_omniauth saml_login: 'new',
                                                first_name: 'first name',
                                                last_name: 'last name',
                                                mail: 'new@example.com',
                                                admin: false
        assert_not_nil new
        assert_in_delta Time.zone.now, new.created_on, 1
      end
    end

    context 'different attribute mappings' do
      setup do
        change_saml_settings onthefly_creation: 1
      end

      should 'map single level attribute' do
        attributes = { saml_login: 'new',
                       first_name: 'first name',
                       last_name: 'last name',
                       mail: 'new@example.com',
                       admin: false }

        new = User.find_or_create_from_omniauth attributes

        assert_not_nil new
        assert_equal attributes[:saml_login], new.login
        assert_equal attributes[:first_name], new.firstname
        assert_equal attributes[:last_name], new.lastname
        assert_equal attributes[:mail], new.mail
        assert_equal attributes[:admin], new.admin
      end

      should 'map nested levels attributes' do
        RedmineSaml.configured_saml[:attribute_mapping_sep] = '|'
        RedmineSaml.configured_saml[:attribute_mapping] = { login: 'one|two|three|four|levels|username',
                                                            firstname: 'one|two|three|four|levels|first_name',
                                                            lastname: 'one|two|three|four|levels|last_name',
                                                            mail: 'one|two|three|four|levels|personal_email',
                                                            admin: 'one|two|three|four|levels|is_admin' }

        real_att = { 'username' => 'new',
                     'first_name' => 'first name',
                     'last_name' => 'last name',
                     'personal_email' => 'mail@example.com',
                     'is_admin' => false }

        attributes = { 'one' => { 'two' => { 'three' => { 'four' => { 'levels' => real_att } } } } }

        new_user = User.find_or_create_from_omniauth attributes

        assert_not_nil new_user

        assert_equal real_att['username'], new_user.login
        assert_equal real_att['first_name'], new_user.firstname
        assert_equal real_att['last_name'], new_user.lastname
        assert_equal real_att['personal_email'], new_user.mail
        assert_equal real_att['is_admin'], new_user.admin
      end
    end

    context 'legacy attribute mapping compatibility' do
      should 'login with only the four required mappings for existing alphanodes initializers' do
        RedmineSaml.configured_saml[:attribute_mapping] = legacy_attribute_mapping
        user = create_legacy_user login: 'legacy-four-mappings',
                                  mail: 'legacy-four-mappings@example.com'

        found_user = User.find_or_create_from_omniauth saml_login: user.login,
                                                       mail: 'mapped@example.com',
                                                       first_name: 'Mapped',
                                                       last_name: 'Name'

        assert_equal user.id, found_user.id
      end

      should 'persist four mapped attributes but not admin for a newly created legacy user' do
        change_saml_settings onthefly_creation: 1
        attributes = { saml_login: 'legacy-new-user',
                       mail: 'legacy-new-user@example.com',
                       first_name: 'Legacy',
                       last_name: 'Created',
                       admin: true }

        new_user = User.find_or_create_from_omniauth attributes
        persisted_user = User.find new_user.id

        assert_equal attributes[:saml_login], persisted_user.login
        assert_equal attributes[:mail], persisted_user.mail
        assert_equal attributes[:first_name], persisted_user.firstname
        assert_equal attributes[:last_name], persisted_user.lastname
        assert_not persisted_user.admin,
                   'existing alphanodes behavior does not apply the optional admin mapping'
      end

      should 'change names only in memory for an existing alphanodes user' do
        user = create_legacy_user login: 'legacy-memory-names',
                                  mail: 'legacy-memory-names@example.com',
                                  firstname: 'Stored First',
                                  lastname: 'Stored Last'

        found_user = User.find_or_create_from_omniauth saml_login: user.login,
                                                       mail: 'changed@example.com',
                                                       first_name: 'Mapped First',
                                                       last_name: 'Mapped Last'

        assert_equal 'Mapped First', found_user.firstname
        assert_equal 'Mapped Last', found_user.lastname
        assert_equal user.login, found_user.login
        assert_equal user.mail, found_user.mail

        found_user.reload
        assert_equal 'Stored First', found_user.firstname
        assert_equal 'Stored Last', found_user.lastname
        assert_equal user.login, found_user.login
        assert_equal user.mail, found_user.mail
      end

      should 'not synchronize login when an existing alphanodes user is found by mail' do
        user = create_legacy_user login: 'legacy-stored-login',
                                  mail: 'legacy-login-lookup@example.com'

        found_user = User.find_or_create_from_omniauth saml_login: 'mapped-login',
                                                       mail: user.mail,
                                                       first_name: 'Mapped First',
                                                       last_name: 'Mapped Last'

        assert_equal user.id, found_user.id
        assert_equal 'legacy-stored-login', found_user.login
        assert_equal 'legacy-stored-login', found_user.reload.login
      end

      should 'not promote an existing alphanodes user through the admin mapping' do
        user = create_legacy_user login: 'legacy-non-admin',
                                  mail: 'legacy-non-admin@example.com',
                                  admin: false

        found_user = User.find_or_create_from_omniauth saml_login: user.login,
                                                       admin: true

        assert_not found_user.admin
        assert_not found_user.reload.admin
      end

      should 'not demote an existing alphanodes admin through the admin mapping' do
        user = create_legacy_user login: 'legacy-admin',
                                  mail: 'legacy-admin@example.com',
                                  admin: true

        found_user = User.find_or_create_from_omniauth saml_login: user.login,
                                                       admin: false

        assert found_user.admin
        assert found_user.reload.admin
      end

      should 'expose mapped names to the legacy on_login hook without persisting them' do
        user = create_legacy_user login: 'legacy-hook-values',
                                  mail: 'legacy-hook-values@example.com',
                                  firstname: 'Stored First',
                                  lastname: 'Stored Last'
        hook_names = nil
        callback = proc { |_omniauth, hook_user| hook_names = [hook_user.firstname, hook_user.lastname] }

        with_on_login_callback callback do
          User.find_or_create_from_omniauth saml_login: user.login,
                                            first_name: 'Hook First',
                                            last_name: 'Hook Last'
        end

        assert_equal ['Hook First', 'Hook Last'], hook_names
        user.reload
        assert_equal 'Stored First', user.firstname
        assert_equal 'Stored Last', user.lastname
      end

      should 'persist mapped names when the legacy on_login hook explicitly saves the user' do
        user = create_legacy_user login: 'legacy-hook-save',
                                  mail: 'legacy-hook-save@example.com',
                                  firstname: 'Stored First',
                                  lastname: 'Stored Last'
        callback = proc { |_omniauth, hook_user| hook_user.save! }

        with_on_login_callback callback do
          User.find_or_create_from_omniauth saml_login: user.login,
                                            first_name: 'Hook First',
                                            last_name: 'Hook Last'
        end

        user.reload
        assert_equal 'Hook First', user.firstname
        assert_equal 'Hook Last', user.lastname
      end
    end
  end

  private

  def legacy_attribute_mapping
    { login: 'saml_login',
      mail: 'mail',
      firstname: 'first_name',
      lastname: 'last_name' }
  end

  def create_legacy_user(login:, mail:, firstname: 'Stored First', lastname: 'Stored Last', admin: false)
    user = User.new firstname: firstname,
                    lastname: lastname,
                    mail: mail,
                    login: login,
                    admin: admin
    assert_save user
    user
  end

  def with_on_login_callback(callback)
    original_callback = RedmineSaml::Base.on_login_callback
    RedmineSaml::Base.on_login(&callback)
    yield
  ensure
    RedmineSaml::Base.on_login(&original_callback)
  end
end
