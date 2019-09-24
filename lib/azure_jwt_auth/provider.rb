require 'net/https'
require 'rsa_pem'

module AzureJwtAuth
  class Provider
    attr_reader :uid, :config_uri, :validations
    attr_reader :config, :keys

    def initialize(uid, config_uri, validations={})
      @uid = uid
      @config_uri = config_uri
      @validations = validations

      http = Net::HTTP.new(URI(config_uri).host, URI(config_uri).port)

      begin
	uri = URI.parse(config_uri)
	http = Net::HTTP.new(uri.host, uri.port)
	http.use_ssl = true
	request = Net::HTTP::Get.new(uri.request_uri)
	response = http.request(request)
	@config = JSON.parse(response.body)
      rescue JSON::ParserError
        raise InvalidProviderConfig, "config_uri response is not valid for provider: #{uid}"
      end

      load_keys
    end

    def load_keys
      uri = URI(@config['jwks_uri'])
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Get.new(uri.request_uri)
      response = http.request(request)
      keys = JSON.parse(response.body)['keys']

      @keys = {}
      keys.each do |key|
        cert = RsaPem.from(key['n'], key['e'])
        rsa = OpenSSL::PKey::RSA.new(cert)

        @keys[key['kid']] = rsa
      end
    end
  end
end
