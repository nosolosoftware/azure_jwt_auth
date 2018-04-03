require 'azure_jwt_auth'
require 'azure_jwt_auth/jwt_manager'

RSpec.describe AzureJwtAuth::JwtManager do
  let(:b2c_uri) { 'https://my-app/v2.0/.well-known/openid-configuration' }
  let(:jwks_uri) { 'https://test.com' }

  let(:issuer) { 'sts.windows.net' }
  let(:audience) { 'my_app_id' }
  let(:kid) { 'key_id' }

  let(:rsa_private) { OpenSSL::PKey::RSA.generate 2048 }
  let(:rsa_public) { rsa_private.public_key }
  let(:key) do
    {
      'kid' => kid,
      'e' => Base64.urlsafe_encode64(rsa_public.params['e'].to_s(2)),
      'n' => Base64.urlsafe_encode64(rsa_public.params['n'].to_s(2))
    }
  end

  # Stub requests to Azure B2C
  def stub_requests
    stub_request(:get, b2c_uri)
      .to_return(body: {'issuer' => issuer, 'jwks_uri' => jwks_uri}.to_json)
    stub_request(:get, jwks_uri)
      .to_return(body: {'keys' => [key]}.to_json)
  end

  context 'when all is ok' do
    it 'works' do
      # test that config is loaded
      stub_requests
      AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

      provider = AzureJwtAuth::JwtManager.providers[:b2c]
      expect(provider.config).to eq('issuer' => issuer, 'jwks_uri' => jwks_uri)
      expect(provider.keys[kid]).not_to be_nil

      # create jwt token
      payload = {'iss' => issuer, 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
      token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => kid)

      # test jwt decode and validation
      request = Rack::Request.new('HTTP_AUTHORIZATION' => token)
      jwt = AzureJwtAuth::JwtManager.new(request, :b2c)
      expect(jwt.valid?).to be_truthy
      expect(jwt.payload).to eq(payload)
    end
  end

  describe '.initializer' do
    context 'when HTTP_AUTHORIZATION header is missing' do
      it 'raises AzureJwtAuth::NotAuthorizationHeader' do
        request = OpenStruct.new(env: {})

        expect {
          AzureJwtAuth::JwtManager.new(request, :b2c)
        }.to raise_error(AzureJwtAuth::NotAuthorizationHeader)
      end
    end

    context 'when provider uid is invalid' do
      it 'raises AzureJwtAuth::ProviderNotFound' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => 'xxx'})
        expect {
          AzureJwtAuth::JwtManager.new(request, :invalid)
        }.to raise_error(AzureJwtAuth::ProviderNotFound)
      end
    end

    context 'when config_uri is not valid' do
      it 'raises AzureJwtAuth::InvalidProviderConfig' do
        # stub requests to Azure B2C
        stub_request(:get, b2c_uri).to_return(status: 404)

        expect {
          AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)
        }.to raise_error(AzureJwtAuth::InvalidProviderConfig)
      end
    end

    context 'when keys are changed' do
      it 'reloads keys' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        # set invalid key
        provider = AzureJwtAuth::JwtManager.providers[:b2c]
        old_rsa_private = OpenSSL::PKey::RSA.generate 2048
        provider.keys[kid] = old_rsa_private

        # create jwt token
        payload = {'iss' => issuer, 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => kid)

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        jwt = AzureJwtAuth::JwtManager.new(request, :b2c)
        expect(jwt.valid?).to be_truthy
      end
    end

    context 'when keys are invalid' do
      it 'raises AzureJwtAuth::KidNotFound' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        # create jwt token
        payload = {'iss' => issuer, 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => 'invalid')

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        expect {
          AzureJwtAuth::JwtManager.new(request, :b2c)
        }.to raise_error(AzureJwtAuth::KidNotFound)
      end
    end

    context 'when jwt signature is invalid' do
      it 'raises JWT::VerificationError' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        # create jwt token
        payload = {'iss' => issuer, 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
        other_rsa_private = OpenSSL::PKey::RSA.generate 2048
        token = JWT.encode(payload, other_rsa_private, 'RS256', 'kid' => kid)

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        expect {
          AzureJwtAuth::JwtManager.new(request, :b2c)
        }.to raise_error(JWT::VerificationError)
      end
    end

    context 'when jwt is expired' do
      it 'raises JWT::ExpiredSignature' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        provider = AzureJwtAuth::JwtManager.providers[:b2c]
        expect(provider.config).to eq('issuer' => issuer, 'jwks_uri' => jwks_uri)
        expect(provider.keys[kid]).not_to be_nil

        # create jwt token
        payload = {'iss' => 'invalid', 'aud' => audience, 'exp' => Time.now.to_i - 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => kid)

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        expect {
          AzureJwtAuth::JwtManager.new(request, :b2c)
        }.to raise_error(JWT::ExpiredSignature)
      end
    end
  end

  describe '#valid?' do
    context 'when jwt iss is invalid' do
      it 'returns false' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri)

        provider = AzureJwtAuth::JwtManager.providers[:b2c]
        expect(provider.config).to eq('issuer' => issuer, 'jwks_uri' => jwks_uri)
        expect(provider.keys[kid]).not_to be_nil

        # create jwt token
        payload = {'iss' => 'invalid', 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => kid)

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        jwt = AzureJwtAuth::JwtManager.new(request, :b2c)
        expect(jwt.valid?).to be_falsey
      end
    end

    context 'when custom validation fail' do
      it 'returns false' do
        # test that config is loaded
        stub_requests
        AzureJwtAuth::JwtManager.load_provider(:b2c, b2c_uri, aud: audience)

        provider = AzureJwtAuth::JwtManager.providers[:b2c]
        expect(provider.config).to eq('issuer' => issuer, 'jwks_uri' => jwks_uri)
        expect(provider.keys[kid]).not_to be_nil

        # create jwt token
        payload = {'iss' => 'invalid', 'aud' => 'invalid', 'exp' => Time.now.to_i + 4 * 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', 'kid' => kid)

        # test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        jwt = AzureJwtAuth::JwtManager.new(request, :b2c)
        expect(jwt.valid?).to be_falsey
      end
    end
  end
end
