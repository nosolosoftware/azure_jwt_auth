require 'azure_jwt_auth'

RSpec.describe AzureJwtAuth::JwtManager do
  let(:b2c_uri) { 'https://my-app/v2.0/.well-known/openid-configuration' }
  let(:jwks_uri) { 'https://test.com' }

  let(:issuer) { 'sts.windows.net' }
  let(:audience) { 'my_app_id' }
  let(:kid) { 'key_id' }

  describe 'b2c authentication' do
    context 'when all is ok' do
      it 'works' do
        # configure AzureJwtAuth
        AzureJwtAuth.b2c_uri = b2c_uri
        AzureJwtAuth.audience = audience

        # generate private/public rsa key
        rsa_private = OpenSSL::PKey::RSA.generate 2048
        rsa_public = rsa_private.public_key
        key = {
          'kid' => kid,
          'e' => Base64.urlsafe_encode64(rsa_public.params['e'].to_s(2)),
          'n' => Base64.urlsafe_encode64(rsa_public.params['n'].to_s(2))
        }

        # stub requests to Azure B2C
        stub_request(:get, b2c_uri).
          to_return(body: {'issuer' => issuer, 'jwks_uri' => jwks_uri}.to_json)
        stub_request(:get, jwks_uri)
          .to_return(body: {'keys' => [key]}.to_json)

        # create jwt token
        payload = {'iss' => issuer, 'aud' => audience, 'exp' => Time.now.to_i + 4 * 3600}
        token = JWT.encode(payload, rsa_private, 'RS256', {'kid' => kid})

        # Test that config is loaded
        AzureJwtAuth::JwtManager.load_config
        expect(AzureJwtAuth::JwtManager.b2c_config).to eq({"issuer"=> issuer, "jwks_uri"=> jwks_uri})
        expect(AzureJwtAuth::JwtManager.b2c_keys[kid]).not_to be_nil

        # Test jwt decode and validation
        request = OpenStruct.new(env: {'HTTP_AUTHORIZATION' => token})
        jwt = AzureJwtAuth::JwtManager.new(request, :b2c)
        expect(jwt.valid?).to be_truthy
        expect(jwt.payload).to eq(payload)
      end
    end
  end
end
