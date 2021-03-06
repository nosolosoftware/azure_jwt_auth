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
      raise NotAuthorizationHeader unless request.env['HTTP_AUTHORIZATION']
      raise ProviderNotFound unless (@provider = self.class.find_provider(provider_id))

      @jwt = request.env['HTTP_AUTHORIZATION'].split.last # remove Bearer
      @jwt_info = JWT.decode(@jwt, nil, false)
    end

    def payload
      @jwt_info ? @jwt_info.first : nil
    end

    def header
      @jwt_info ? @jwt_info.last : nil
    end

    # Validates issuer
    def iss_valid?
      payload['iss'] == @provider.config['issuer'] || # b2c
        (payload['tid'] && @provider.config['issuer'] =~ /#{payload['tid']}/) # ac
    end

    # Check custom validations defined into provider
    def custom_valid?
      @provider.validations.each do |key, value|
        return false unless payload[key] == value
      end

      true
    end

    # Validates the payload hash for expiration and meta claims
    def valid?
      payload && iss_valid? && custom_valid? && rsa_decode
    end

    private

    # Decodes the JWT with the signed secret
    def rsa_decode
      kid = header['kid']
      try = false

      begin
        rsa = @provider.keys[kid]
        raise KidNotFound, 'kid not found into provider keys' unless rsa

        JWT.decode(@jwt, rsa.public_key, true, algorithm: 'RS256')
      rescue JWT::VerificationError, KidNotFound
        raise if try

        @provider.load_keys # maybe keys have been changed
        try = true
        retry
      end
    end
  end
end
