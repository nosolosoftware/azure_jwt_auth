require 'azure_jwt_auth/provider'
require 'jwt'

module AzureJwtAuth
  class JwtManager
    class << self
      attr_reader :providers

      def load_provider(uid, config_uri, validations={})
        @providers ||= {}
        @providers[uid] = Provider.new(uid, config_uri, validations)
      end

      def find_provider(uid)
        return unless @providers
        @providers[uid]
      end
    end

    def initialize(request, provider_id)
      raise 'NOT AUTHORIZATION HEADER' unless request.env['HTTP_AUTHORIZATION']
      raise 'PROVIDER NOT FOUND' unless (@provider = self.class.find_provider(provider_id))

      @jwt = request.env['HTTP_AUTHORIZATION'].split.last # remove Bearer
      @jwt_info = decode
    end

    def payload
      @jwt_info ? @jwt_info.first : nil
    end

    # Validates the payload hash for expiration and meta claims
    def valid?
      payload && !expired? && iss_valid? && custom_valid?
    end

    # Validates if the token is expired by exp parameter
    def expired?
      Time.at(payload['exp']) < Time.now
    end

    # Check custom validations defined into provider
    def custom_valid?
      @provider.validations.each do |key, value|
        return false unless payload[key] == value
      end

      true
    end

    # Validates issuer
    def iss_valid?
      payload['iss'] == @provider.config['issuer']
    end

    private

    # Decodes the JWT with the signed secret
    def decode
      dirty_token = JWT.decode(@jwt, nil, false)
      kid = dirty_token.last['kid']
      try = false

      begin
        rsa = @provider.keys[kid]
        JWT.decode(@jwt, rsa.public_key, true, algorithm: 'RS256')
      rescue JWT::VerificationError
        raise if try

        @provider.load_keys # maybe keys have been changed
        try = true
        retry
      end
    end
  end
end
