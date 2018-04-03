# AzureJwtAuth

Easy way for Ruby applications to authenticate to Azure B2C/AD in order to access protected web resources.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'azure_jwt_auth'
```

And then execute:

```bash
$ bundle
```

Or install it yourself as:

```bash
$ gem install azure_jwt_auth
```

## Usage with Rails

First of all, we add our providers into an initializer:

```ruby
# config/initializers/azure.rb

require 'azure_jwt_auth/jwt_manager'

AzureJwtAuth::JwtManager.load_provider(
  :b2c,
  'https://login.microsoftonline.com/.../v2.0/.well-known/openid-configuration')
)

AzureJwtAuth::JwtManager.load_provider(
  :ad,
  'https://sts.windows.net/.../v2.0/.well-known/openid-configuration'
)
...
```

Then, we add `Authenticable` module into `ApplicationController` and define `entity_from_token_payload` method.  
This method is used by `Authenticable` module to load `current_user`.

```ruby
require 'azure_jwt_auth/authenticable'

class ApplicationController < ActionController::API
  include AzureJwtAuth::Authenticable

  rescue_from AzureJwtAuth::NotAuthorized, with: :render_401

  private

  def render_401
    render json: {}, status: 401
  end

  def entity_from_token_payload(payload)
    # Returns a valid entity, `nil` or raise
    # e.g.
    #   User.find payload['sub']
  end
end
```

Finally, we can use `authenticate!` method into ours controllers:

```ruby
class ExampleController < ApplicationController
  before_action :authenticate!

  ...
end
```

## Providers

Provider class initializer receives the following parameters:

| parameter   | description |
| --          | --          |
| uid         | unique provider identifier |
| config_url  | azure url to get config |
| validations | payload fields validations which will be checked for each token: `{payload_field: value_expected, ...}` (optional) |

We create providers using the `AzureJwtAuth::JwtManager.load_provider` method:

```ruby
AzureJwtAuth::JwtManager.load_provider(
  :b2c, # uid
  'https://login.microsoftonline.com/.../v2.0/.well-known/openid-configuration'), # config_url
  {'aud' => 'my_app_id'} # validations
)
```

## Authenticable

[This module](lib/azure_jwt_auth/authenticable.rb) provides us with the following methods:

* __authenticate!__

  Check if a token is valid for any provider and loads `current_user`. Otherwise it throws an exception.

  If you need other behavior you can define your custom authenticate! method like this:

  ```ruby
  def my_authenticate!
    begin
      token = JwtManager.new(request, :privider_id)
      unauthorize! unless token.valid?
    rescue
      unauthorize!
    end

    @current_user = User.find(token.payload['sub'])
  end
  ```

* __current_user__

  Returns current_user loaded by `authenticate!` method.

* __signed_in?__

  Check if exists current_user.

* __unauthorize!__

  Throws a `AzureJwtAuth::NotAuthorized` exception.

## Testing (rspec)

Require the [AzureJwtAuth::Spec::Helpers](lib/azure_jwt_auth/spec/helpers.rb) helper module in `rails_helper.rb`.

```ruby
  require 'azure_jwt_auth/spec/helpers'
  ...
  RSpec.configure do |config|
    ...
    config.include AzureJwtAuth::Spec::Helpers, :type => :controller
  end
```

And then we can just call `sign_in(user)`:

```ruby
  describe ExampleController
    let(:user) { MyEntity.create(...) }

    it "blocks unauthenticated access" do
      get :index
      expect(response).to have_http_status(401)
    end

    it "allows authenticated access" do
      sign_in user # user will be returned by current_user method
      get :index
      expect(response).to have_http_status(200)
    end
  end
```

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
