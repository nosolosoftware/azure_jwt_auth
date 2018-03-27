$:.push File.expand_path('../lib', __FILE__)

# Maintain your gem's version:
require 'azure_jwt_auth/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = 'azure_jwt_auth'
  s.version     = AzureJwtAuth::VERSION
  s.authors     = ['rjurado']
  s.email       = ['rjurado@openmailbox.org']
  s.homepage    = 'https://github.com/rjurado01/rails_jwt_auth'
  s.summary     = 'Rails jwt authentication.'
  s.description = 'Rails authentication solution using Azure B2C.'
  s.license     = 'MIT'

  s.files = Dir['{app,config,db,lib}/**/*', 'MIT-LICENSE', 'Rakefile', 'README.md']

  s.add_dependency 'bcrypt',                '~> 3.1'
  s.add_dependency 'jwt',                   '~> 1.5'
  s.add_dependency 'rsa-pem-from-mod-exp',  '~> 0.1'
end
