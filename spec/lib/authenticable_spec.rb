require 'azure_jwt_auth/authenticable'

RSpec.describe AzureJwtAuth::Authenticable do
  let(:dummy_class) do
    Class.new do
      include AzureJwtAuth::Authenticable

      attr_accessor :request

      def entity_from_token_payload(_payload)
        {}
      end
    end
  end

  let(:dummy_item) { dummy_class.new }

  context 'when all is ok' do
    it 'loads current_user' do
      provider = Object.new
      allow(provider).to receive(:uid).and_return('uid')
      allow(AzureJwtAuth::JwtManager).to receive(:providers).and_return('uid' => provider)

      token = Object.new
      allow(token).to receive(:valid?).and_return(true)
      allow(token).to receive(:payload).and_return({})
      allow(AzureJwtAuth::JwtManager).to receive(:new).and_return(token)

      dummy_item.request = Rack::Request.new('HTTP_AUTHORIZATION' => 'xxx')
      dummy_item.authenticate!
      expect(dummy_item.send(:current_user)).to eq({})
    end
  end

  context 'when there are not providers' do
    it 'calls unauthorize!' do
      expect {
        dummy_item.authenticate!
      }.to raise_error(AzureJwtAuth::NotAuthorized)
    end
  end

  context 'when JwtManager.new raise exception' do
    it 'calls unauthorize!' do
      provider = Object.new
      allow(provider).to receive(:uid).and_return('uid')
      allow(AzureJwtAuth::JwtManager).to receive(:providers).and_return('uid' => provider)

      allow(AzureJwtAuth::JwtManager).to receive(:new).and_raise('Exception')

      expect {
        dummy_item.request = Rack::Request.new('HTTP_AUTHORIZATION' => 'xxx')
        dummy_item.authenticate!
      }.to raise_error(AzureJwtAuth::NotAuthorized)
    end
  end

  context 'when token is invalid' do
    it 'calls unauthorize!' do
      provider = Object.new
      allow(provider).to receive(:uid).and_return('uid')
      allow(AzureJwtAuth::JwtManager).to receive(:providers).and_return('uid' => provider)

      token = Object.new
      allow(token).to receive(:valid?).and_return(false)
      allow(AzureJwtAuth::JwtManager).to receive(:new).and_return(token)

      dummy_item.request = Rack::Request.new('HTTP_AUTHORIZATION' => 'xxx')
      expect { dummy_item.authenticate! }.to raise_error(AzureJwtAuth::NotAuthorized)
    end
  end
end
