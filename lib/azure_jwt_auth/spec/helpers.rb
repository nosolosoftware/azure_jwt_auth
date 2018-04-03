module AzureJwtAuth
  module Spec
    module Helpers
      require 'azure_jwt_auth/jwt_manager'

      def sign_in(user)
        allow(controller).to receive(:authenticate!).and_return(true)
        allow(controller).to receive(:current_user).and_return(user)
      end
    end
  end
end
