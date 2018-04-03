require 'bcrypt'

module AzureJwtAuth
  KidNotFound = Class.new(StandardError)
  InvalidProviderConfig = Class.new(StandardError)
  NotAuthorizationHeader = Class.new(StandardError)
  ProviderNotFound = Class.new(StandardError)
end
