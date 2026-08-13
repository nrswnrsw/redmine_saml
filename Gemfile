# frozen_string_literal: true

gem 'omniauth-rails_csrf_protection', '>= 1.0.2', '!= 2.0.0'
gem 'omniauth-saml', '>= 2.2.4'
gem 'redmine_plugin_kit'
gem 'ruby-saml', '>= 1.18.1'
gem 'slim-rails'

group :test do
  gem 'shoulda-context', '3.0.0.rc1'
  gem 'shoulda-matchers'
end

group :development do
  # this is only used for development.
  # if you want to use it, do:
  # - create .enable_dev file in redmine_saml directory
  # - remove rubocop entries from REDMINE/Gemfile
  # - remove REDMINE/.rubocop* files
  if File.file? File.expand_path './.enable_dev', __dir__
    gem 'brakeman', require: false
    gem 'pandoc-ruby', require: false
    gem 'rubocop', require: false
    gem 'rubocop-performance', require: false
    gem 'rubocop-rails', require: false
    gem 'slim_lint', require: false
  end
end
