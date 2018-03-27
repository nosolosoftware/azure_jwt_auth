require 'azure_jwt_auth/jwt_manager'

module AzureJwtAuth
  module Authenticable
    AzureJwtAuth::NotAuthorized = Class.new(StandardError)

    def current_user
      @current_user
    end

    def signed_in?
      !current_user.nil?
    end

    def authenticate!
      begin
        token = JwtManager.new(request)
        unauthorize! unless token.valid?
      rescue RuntimeError, JWT::DecodeError
        unauthorize!
      end

      @current_user = AzureJwtAuth.model.from_token_payload(token.payload)
    end

    def unauthorize!
      raise NotAuthorized
    end
  end
end
