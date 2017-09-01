# -*- coding:utf-8 -*-

require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'jwt'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: "https",
        host: nil,
        port: nil,
        authorization_endpoint: "/authorize",
        token_endpoint: "/token",
        userinfo_endpoint: "/userinfo",
        jwks_uri: '/jwk'
      }
      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key

      option :name, nil  # 必須. こちらが provider 名になる
      option :scope, [:openid]
      option :response_type, "code"
      option :state
      option :response_mode
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :login_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website }
        }
      end

      extra do
        {raw_info: user_info.raw_attributes}
      end

      credentials do
        {
            id_token: access_token.id_token,
            token: access_token.access_token,
            refresh_token: access_token.refresh_token,
            expires_in: access_token.expires_in,
            scope: access_token.scope
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)

        return @config
      end

      def request_phase
        if client_options.scheme == "http"
          WebFinger.url_builder = URI::HTTP
          SWD.url_builder = URI::HTTP
        end

        options.issuer = issuer if options.issuer.blank?
        discover! if options.discovery
        redirect authorize_uri
      end

      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        #elsif request.params['state'].to_s.empty? || request.params['state'] != stored_state
        #  return Rack::Response.new(['401 Unauthorized'], 401).finish
        elsif !request.params["code"]
          return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(request.params["error"]))
        else
          options.issuer = issuer if options.issuer.blank?
          discover! if options.discovery
          client.redirect_uri = client_options.redirect_uri
          client.authorization_code = authorization_code
          access_token

          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end


      def authorization_code
        request.params["code"]
      end

      def authorize_uri
        client.redirect_uri = client_options.redirect_uri
        opts = {
            response_type: options.response_type,
            scope: options.scope,
            state: new_state,
            nonce: (new_nonce if options.send_nonce),
            hd: options.hd,
            prompt: options.prompt
        }
        if request.params['email']
          opts[:email] = request.params['email']
        end
        if request.params['realm']
          opts[:realm] = request.params['realm']
        end
        if request.params['cid']
          opts[:cid] = request.params['cid']
        end
        client.authorization_uri(opts.reject{|k,v| v.nil?})
      end


      def public_key(kid=nil)
        if options.discovery && kid.present?
          key = config.jwks.select{|k| k["kid"] == kid}.try(:first)
          JSON::JWK.new(key).to_key
        else
          key_or_secret
        end
      end

      private

      def issuer
        resource = "#{client_options.scheme}://#{client_options.host}" + ((client_options.port) ? ":#{client_options.port.to_s}" : '')

        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri
      end

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def access_token
        @access_token ||= lambda {
          begin
            configure_http_client_ssl if client_options.ssl.certificate.present? && client_options.ssl.private_key.present?
            _access_token = client.access_token!(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
            )
          ensure
            reset_http_client
          end

          header = ::JWT.decoded_segments(_access_token.id_token, false).try(:[],0)
          kid = header["kid"]
          key = public_key(kid)
          _id_token = decode_id_token _access_token.id_token, key

          _id_token.verify!(
              issuer: options.issuer,
              client_id: client_options.identifier,
              nonce: stored_nonce
          )
          _access_token
        }.call()
      end


      def configure_http_client_ssl
        Rack::OAuth2.http_config do |http_client|
          http_client.ssl_config.client_cert = client_options.ssl.certificate
          http_client.ssl_config.client_key = client_options.ssl.private_key
        end
      end

      def reset_http_client
        Rack::OAuth2.reset_http_config!
      end


      def decode_id_token(id_token, key)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key)
      end

      def client_options
        options.client_options
      end


      def new_state
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def session
        @env.nil? ? {} : super
      end

      def key_or_secret
        case options.client_signing_alg
          when :HS256, :HS384, :HS512
            return client_options.secret

          when :RS256, :RS384, :RS512
            if options.client_jwk_signing_key
              return parse_jwk_key(options.client_jwk_signing_key.to_hash)
            elsif options.client_x509_signing_key
              return parse_x509_key(options.client_x509_signing_key)
            end
          else
            if(client_options.secret)
              return client_options.secret
            end
        end
        return nil
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = JSON.parse(key)
        if json.has_key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end

=begin
      def create_rsa_key(mod, exp)
        key = OpenSSL::PKey::RSA.new
        exponent = OpenSSL::BN.new decode(exp)
        modulus = OpenSSL::BN.new decode(mod)
        key.e = exponent
        key.n = modulus
        key
=end
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
