$:.push File.expand_path('../lib', __FILE__)

# Maintain your gem's version:
require 'azure_jwt_auth/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = 'azure_jwt_auth'
  s.version     = AzureJwtAuth::VERSION
  s.authors     = ['rjurado']
  s.email       = ['rjurado@nosolosoftware.es']
  s.homepage    = 'https://github.com/nosolosoftware/azure_jwt_auth'
  s.summary     = 'Azure B2C/AD authentication using Ruby.'
  s.description = 'Easy way for Ruby applications to authenticate to Azure B2C/AD in order to access protected web resources.'
  s.license     = 'MIT'

  s.files = Dir['{app,config,db,lib}/**/*', 'MIT-LICENSE', 'Rakefile', 'README.md']

  s.add_dependency 'bcrypt',                '~> 3.1'
  s.add_dependency 'jwt',                   '~> 2.2'
  s.add_dependency 'rsa-pem-from-mod-exp',  '~> 0.1'
end
