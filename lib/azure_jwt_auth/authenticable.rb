require 'azure_jwt_auth/jwt_manager'

module AzureJwtAuth
  AzureJwtAuth::NotAuthorized = Class.new(StandardError)

  module Authenticable
    def current_user
      @current_user
    end

    def signed_in?
      !current_user.nil?
    end

    def authenticate!
      unauthorize! unless JwtManager.providers

      JwtManager.providers.each do |_uid, provider|
	begin
          token = JwtManager.new(request, provider.uid)
          if token.valid?
            @current_user = entity_from_token_payload(token.payload)
            break
          end
	rescue => error
	  Rails.logger.info(error) if defined? Rails
        end
      end
      unauthorize! unless @current_user
    end

    def unauthorize!
      raise NotAuthorized
    end
  end
end
