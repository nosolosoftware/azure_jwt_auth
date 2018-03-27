RSpec.describe AzureJwtAuth::Authenticable do
  let(:dummy_class) do
    Class.new do
      include AzureJwtAuth::Authenticable

      attr_accessor :request
    end
  end

  let(:dummy_item) { dummy_class.new }

  let(:token) { 'xxx' }

  xit 'xample' do
    dummy_item.request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
    dummy_item.authenticate!
  end
end
