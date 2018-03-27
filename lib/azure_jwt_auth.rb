require 'bcrypt'

module AzureJwtAuth
  class << self
    attr_accessor :audience
    attr_accessor :b2c_uri
    attr_accessor :ad_uri
  end

  def self.setup
    yield self
  end
end
