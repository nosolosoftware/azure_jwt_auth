require 'net/http'
require 'rsa_pem'

module AzureJwtAuth
  class Provider
    attr_reader :uid, :config_uri, :validations
    attr_reader :config, :keys

    def initialize(uid, config_uri, validations={})
      @uid = uid
      @config_uri = config_uri
      @validations = validations

      @config = JSON.parse(Net::HTTP.get(URI(config_uri)))
      load_keys
    end

    def load_keys
      uri = URI(@config['jwks_uri'])
      keys = JSON.parse(Net::HTTP.get(uri))['keys']

      @keys = {}
      keys.each do |key|
        cert = RsaPem.from(key['n'], key['e'])
        rsa = OpenSSL::PKey::RSA.new(cert)

        @keys[key['kid']] = rsa
      end
    end
  end
end
