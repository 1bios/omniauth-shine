require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Shine < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'activity'

      option :client_options, {
        :site => 'https://api.misfitwearables.com',
        :authorize_url => '/auth/dialog/authorize',
        :token_url => '/auth/tokens/exchange',
      }

      # provider does not really ignore state, but am getting
      # error when returning via the moves: scheme link.
      # option :provider_ignores_state, true

      uid {
        raw_info['userId']
      }

      info do
        {
          :name => raw_info['name'],
          :email => raw_info['email'],
          :avatar => raw_info['avatar'],
          :birthday => raw_info['birthday'],
          :gender => raw_info['gender']
        }
      end

      extra do
        {
          :raw_info => raw_info
        }
      end

      def request_phase
        options[:authorize_params] = client_params.merge(options[:authorize_params])
        super
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super, client_params.merge({:grant_type => 'authorization_code'}))
      end

      def raw_info
        @raw_info ||= access_token.get('/move/resource/v1/user/me/profile').parsed
      end

      def callback_url
        full_host + script_name + callback_path
      end

      private

      def client_params
        {:client_id => options[:client_id], :redirect_uri => callback_url ,:response_type => 'code', :scope => DEFAULT_SCOPE}
      end
    end
  end
end
