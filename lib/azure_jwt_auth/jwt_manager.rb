require 'net/http'
require 'jwt'
require 'rsa_pem'

module AzureJwtAuth
  class JwtManager
    class << self
      attr_reader :b2c_config, :ad_config, :b2c_keys, :ad_keys

      def load_config
        if AzureJwtAuth.b2c_uri
          @b2c_config = JSON.parse(Net::HTTP.get(URI(AzureJwtAuth.b2c_uri)))
          load_b2c_keys if @b2c_config
        end

        if AzureJwtAuth.ad_uri
          @ad_config = JSON.parse(Net::HTTP.get(URI(AzureJwtAuth.ad_uri)))
          load_ad_keys if @ad_config
        end
      end

      def load_b2c_keys
        uri = URI(@b2c_config['jwks_uri'])
        keys = JSON.parse(Net::HTTP.get(uri))['keys']

        @b2c_keys = {}
        keys.each do |key|
          cert = RsaPem.from(key['n'], key['e'])
          rsa = OpenSSL::PKey::RSA.new(cert)

          @b2c_keys[key['kid']] = rsa
        end
      end

      def load_ad_keys
        uri = URI(@ad_config['jwks_uri'])
        keys = JSON.parse(Net::HTTP.get(uri))['keys']

        @ad_keys = {}
        keys.each do |key|
          cert = RsaPem.from(key['n'], key['e'])
          rsa = OpenSSL::PKey::RSA.new(cert)

          @ad_keys[key['kid']] = rsa
        end
      end
    end

    def initialize(request, type=:b2c)
      raise 'NOT AUTHORIZATION HEADER' unless request.env['HTTP_AUTHORIZATION']

      @type = type
      @jwt = request.env['HTTP_AUTHORIZATION'].split.last # remove Bearer
      @jwt_info = decode
    end

    def payload
      @jwt_info ? @jwt_info.first : nil
    end

    # Validates the payload hash for expiration and meta claims
    def valid?
      payload && !expired? && aud_valid? && iss_valid?
    end

    # Validates if the token is expired by exp parameter
    def expired?
      Time.at(payload['exp']) < Time.now
    end

    # Validates audence
    def aud_valid?
      payload['aud'] == AzureJwtAuth.audience
    end

    # Validates issuer
    def iss_valid?
      payload['iss'] == self.class.send("#{@type}_config")['issuer']
    end

    private

    # Decodes the JWT with the signed secret
    def decode
      dirty_token = JWT.decode(@jwt, nil, false)
      kid = dirty_token.last['kid']
      try = false

      begin
        rsa = keys[kid]
        JWT.decode(@jwt, rsa.public_key, true, algorithm: 'RS256')
      rescue JWT::VerificationError
        raise if try

        load_keys # maybe keys have been changed
        try = true
        retry
      end
    end

    # Returns instance type rsa keys
    def keys
      self.class.send("#{@type}_keys")
    end

    # Loads keys from Azure B2C for instance type
    def load_keys
      self.class.send("load_#{@type}_keys")
    end
  end
end
