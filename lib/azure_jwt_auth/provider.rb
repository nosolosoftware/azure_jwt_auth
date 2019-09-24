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

      begin
	request = Net:HTTP::Get.new(URI(config_uri).request_uri)
	@config = JSON.parse(http.request(request))
      rescue JSON::ParserError
        raise InvalidProviderConfig, "config_uri response is not valid for provider: #{uid}"
      end

      load_keys
    end

    def load_keys
      uri = URI(@config['jwks_uri'])
      request = Net:HTTP::Get.new(URI(uri).request_uri)
      keys = JSON.parse(http.request(request))['keys']

      @keys = {}
      keys.each do |key|
        cert = RsaPem.from(key['n'], key['e'])
        rsa = OpenSSL::PKey::RSA.new(cert)

        @keys[key['kid']] = rsa
      end
    end
  end
end
