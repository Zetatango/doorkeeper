require 'spec_helper_integration'

describe Doorkeeper::TokensController do
  describe 'when authorization has succeeded' do
    let :token do
      double(:token, authorize: true)
    end

    before do
      allow(controller).to receive(:token) { token }
    end

    it 'returns the authorization' do
      skip 'verify need of these specs'

      expect(token).to receive(:authorization)

      post :create
    end
  end

  describe 'when authorization has failed' do
    it 'returns the error response' do
      token = double(:token, authorize: false)
      allow(controller).to receive(:token) { token }

      post :create

      expect(response.status).to eq 401
      expect(response.headers['WWW-Authenticate']).to match(/Bearer/)
    end
  end

  describe 'when there is a failure due to a custom error' do
    it 'returns the error response with a custom message' do
      # I18n looks for `doorkeeper.errors.messages.custom_message` in locale files
      custom_message = "my_message"
      allow(I18n).to receive(:translate).
        with(
          custom_message,
          hash_including(scope: [:doorkeeper, :errors, :messages]),
        ).
        and_return('Authorization custom message')

      doorkeeper_error = Doorkeeper::Errors::DoorkeeperError.new(custom_message)

      strategy = double(:strategy)
      request = double(token_request: strategy)
      allow(strategy).to receive(:authorize).and_raise(doorkeeper_error)
      allow(controller).to receive(:server).and_return(request)

      post :create

      expected_response_body = {
        "error"             => custom_message,
        "error_description" => "Authorization custom message"
      }
      expect(response.status).to eq 401
      expect(response.headers['WWW-Authenticate']).to match(/Bearer/)
      expect(JSON.load(response.body)).to eq expected_response_body
    end
  end
     # http://tools.ietf.org/html/rfc7009#section-2.2
    describe 'revoking tokens' do
      let(:client) { FactoryBot.create(:application) }
      let(:access_token) { FactoryBot.create(:access_token, application: client) }

      before(:each) do
        allow(controller).to receive(:token) { access_token }
      end

      context 'when associated app is public' do
        let(:client) { FactoryBot.create(:application, confidential: false) }

        it 'returns 200' do
          post :revoke

          expect(response.status).to eq 200
        end

        it 'revokes the access token' do
          post :revoke

          expect(access_token.reload).to have_attributes(revoked?: true)
        end
      end

      context 'when associated app is confidential' do
        let(:client) { FactoryBot.create(:application, confidential: true) }
        let(:oauth_client) { Doorkeeper::OAuth::Client.new(client) }

        before(:each) do
          allow_any_instance_of(Doorkeeper::Server).to receive(:client) { oauth_client }
        end

        it 'returns 200' do
          post :revoke

          expect(response.status).to eq 200
        end

        it 'revokes the access token' do
          post :revoke

          expect(access_token.reload).to have_attributes(revoked?: true)
        end

        context 'when authorization fails' do
          let(:some_other_client) { FactoryBot.create(:application, confidential: true) }
          let(:oauth_client) { Doorkeeper::OAuth::Client.new(some_other_client) }

        it 'returns 200' do
          post :revoke

          expect(response.status).to eq 200
        end

        it 'does not revoke the access token' do
          post :revoke

          expect(access_token.reload).to have_attributes(revoked?: false)
        end
      end
    end
  end

  describe 'authorize response memoization' do
    it "memoizes the result of the authorization" do
      strategy = double(:strategy, authorize: true)
      expect(strategy).to receive(:authorize).once
      allow(controller).to receive(:strategy) { strategy }
      allow(controller).to receive(:create) do
        controller.send :authorize_response
      end

      post :create
    end
  end
end
