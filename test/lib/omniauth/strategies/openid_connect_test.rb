# -*- coding:utf-8 -*-
require_relative '../../../test_helper'


module OmniAuth
  module Strategies
    class OpenIDConnectTest < StrategyTestCase
      def test_client_options_defaults
        assert_equal 'https', strategy.options.client_options.scheme
        assert_nil strategy.options.client_options.port
        assert_equal '/authorize', strategy.options.client_options.authorization_endpoint
        assert_equal '/token', strategy.options.client_options.token_endpoint
      end


      def test_uid
        assert_equal user_info.sub, strategy.uid

        strategy.options.uid_field = 'preferred_username'
        assert_equal user_info.preferred_username, strategy.uid

        strategy.options.uid_field = 'something'
        assert_equal user_info.sub, strategy.uid
      end


      ##################################################################
      # request phase

      def test_request_phase
        expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w]{32}&response_type=code&scope=openid&state=[\w]{32}$/
        strategy.options.issuer = 'https://example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end


      def test_request_phase_with_params
        expected_redirect = /^https:\/\/example\.com\/authorize\?claims_locales=es&client_id=1234&login_hint=john.doe%40example.com&nonce=\w{32}&response_type=code&scope=openid&state=\w{32}&ui_locales=en$/
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        request.stubs(:params).returns('login_hint' => 'john.doe@example.com', 'ui_locales' => 'en', 'claims_locales' => 'es')

        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end


      def test_request_phase_with_discovery
        expected_redirect = /^https:\/\/example\.com\/authorization\?client_id=1234&nonce=[\w]{32}&response_type=code&scope=openid&state=[\w]{32}$/
        strategy.options.client_options.host = 'example.com'
        strategy.options.discovery = true

        config = MiniTest::Mock.new('OpenIDConnect::Discovery::Provider::Config')
        config.stubs(:authorization_endpoint).returns('https://example.com/authorization')
        config.stubs(:token_endpoint).returns('https://example.com/token')
        config.stubs(:userinfo_endpoint).returns('https://example.com/userinfo')
        config.stubs(:jwks_uri).returns('https://example.com/jwks')
        ::OpenIDConnect::Discovery::Provider::Config.stubs(:discover!).with('https://example.com').returns(config)

        strategy.setup_phase
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase

        assert_equal nil, strategy.options.issuer
        assert_equal strategy.options.client_options.authorization_endpoint, 'https://example.com/authorization'
        assert_equal strategy.options.client_options.token_endpoint, 'https://example.com/token'
        assert_equal strategy.options.client_options.userinfo_endpoint, 'https://example.com/userinfo'
        #assert_equal strategy.options.client_options.jwks_uri, 'https://example.com/jwks'
      end


      def test_request_phase_with_prompt
        expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w]{32}&prompt=login%2Cselect_account&response_type=code&scope=openid&state=[\w]{32}$/
        strategy.options.prompt = 'login,select_account'
        strategy.options.issuer = 'https://example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      def test_request_phase_with_ux
        expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w]{32}&response_type=code&scope=openid&state=[\w]{32}&ux=signup%2Ccustom_message$/
        strategy.options.ux = 'signup,custom_message'
        strategy.options.issuer = 'https://example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end


      def test_request_phase_with_ui_locales
        expected_redirect = /^https:\/\/example\.com\/authorize\?client_id=1234&nonce=[\w]{32}&response_type=code&scope=openid&state=[\w]{32}&ui_locales=fr\+en$/
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        request.stubs(:params).returns({'ui_locales' => 'fr en'})
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end


      def test_request_phase_via_http
        expected_redirect = /^http:\/\/.*$/
        strategy.options.client_options.scheme = 'http'
        strategy.options.issuer = 'example.com'
        strategy.options.client_options.host = 'example.com'
        strategy.expects(:redirect).with(regexp_matches(expected_redirect))
        strategy.request_phase
      end

      ##################################################################
      # callback phase

      def test_callback_phase_with_error
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('error' => 'invalid_request')
        request.stubs(:path_info).returns('')

        strategy.call!('rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce})
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_callback_phase_without_code
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('state' => state)
        request.stubs(:path_info).returns('')

        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)
        strategy.callback_phase
      end


      # Timeout::Error  timeout() がタイムアウトすると発生.
      def test_callback_phase_with_timeout
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = 'http://example.com'

        strategy.stubs(:build_access_token).raises(::Timeout::Error.new('error'))
        strategy.call!('rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce})
        strategy.expects(:fail!)
        strategy.callback_phase
      end


      # Errno::ETIMEDOUT  システムエラー
      def test_callback_phase_with_etimedout
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code,'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = 'http://example.com'

        strategy.stubs(:build_access_token).raises(::Errno::ETIMEDOUT.new('error'))
        strategy.call!('rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce})
        strategy.expects(:fail!)
        strategy.callback_phase
      end


      def test_callback_phase_with_socket_error
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code,'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.issuer = 'http://example.com'

        strategy.stubs(:build_access_token).raises(::SocketError.new('error'))
        strategy.call!('rack.session' => {'omniauth.state' => state, 'omniauth.nonce' => nonce})
        strategy.expects(:fail!)
        strategy.callback_phase
      end

      def test_callback_phase_with_rack_oauth2_client_error
        code = SecureRandom.hex(16)
        state = SecureRandom.hex(16)
        nonce = SecureRandom.hex(16)
        request.stubs(:params).returns('code' => code, 'state' => state)
        request.stubs(:path_info).returns('')

        strategy.options.client_options.host = 'example.com'

        strategy.stubs(:access_token).raises(::Rack::OAuth2::Client::Error.new('error', error: 'Unknown'))
        strategy.call!('rack.session' => { 'omniauth.state' => state, 'omniauth.nonce' => nonce })
        strategy.expects(:fail!)
        strategy.callback_phase
      end


      def test_info
        info = strategy.info
        assert_equal user_info.name, info[:name]
        assert_equal user_info.email, info[:email]
        assert_equal user_info.preferred_username, info[:nickname]
        assert_equal user_info.given_name, info[:first_name]
        assert_equal user_info.family_name, info[:last_name]
        assert_equal user_info.gender, info[:gender]
        assert_equal user_info.picture, info[:image]
        assert_equal user_info.phone_number, info[:phone]
        assert_equal({ website: user_info.website }, info[:urls])
      end

      def test_extra
        assert_equal({ raw_info: user_info.as_json }, strategy.extra)
      end

      def test_option_send_nonce
        strategy.options.client_options[:host] = 'foobar.com'

        assert(strategy.client.authorization_uri(strategy.authorize_params) =~ /nonce=/, 'URI must contain nonce')

        strategy.options.send_nonce = false
        assert(strategy.client.authorization_uri(strategy.authorize_params) !~ /nonce=/, 'URI must not contain nonce')
      end

      def test_public_key_with_jwks
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_jwk_signing_key = File.read('./test/fixtures/jwks.json')

        assert_equal JSON::JWK::Set, strategy.public_key.class
      end


      def test_public_key_with_jwk
        strategy.options.client_signing_alg = :RS256
        jwks_str = File.read('./test/fixtures/jwks.json')
        jwks = JSON.parse(jwks_str)
        jwk = jwks['keys'].first
        strategy.options.client_jwk_signing_key = jwk # .to_json

        assert_equal JSON::JWK, strategy.public_key.class
      end

      def test_public_key_with_x509
        strategy.options.client_signing_alg = :RS256
        strategy.options.client_x509_signing_key = File.read('./test/fixtures/test.crt')
        assert_equal OpenSSL::PKey::RSA, strategy.public_key.class
      end

    end # of class OpenIDConnectTest
  end
end
