require 'timeout'
require 'net/http'
require 'omniauth'
require 'openid_connect'
require 'jwt'


module OmniAuth
  module Strategies

    # Authentication strategy using OpenID Connect
    # Specification::
    #     http://openid.net/specs/openid-connect-core-1_0.html
    class OpenIDConnect
      # OmniAuth::Strategies::OAuth2 から派生させるのは大変.
      # - openid_connect が rack-oauth2, json-jwt に依存している
      # - 他方, omniauth-oauth2 は, oauth2, jwt に依存. その書き換えも必要.
      include OmniAuth::Strategy

      # OpenIDConnect::Client.new() に渡されるオプション.
      option :client_options,
             # Authentication Request: [REQUIRED] client_id
             identifier: nil,

             # Authentication Request: [REQUIRED] client_secret
             secret: nil,

             # Authentication Request: [REQUIRED]
             redirect_uri: nil,

             # [REQUIRED] authorization_endpoint のホスト.
             scheme: 'https',
             host: nil,
             port: nil,

             # discovery: falseの時に指定.
             authorization_endpoint: '/authorize',
             token_endpoint: '/token',
             userinfo_endpoint: '/userinfo',
             expires_in: nil

      # 指定しなかった場合は, client_options.{scheme, host, port} から作られる.
      option :issuer

      option :discovery, false

      option :client_jwk_signing_key
      option :client_x509_signing_key

      # 必須. こちらが route URL の provider 名になる
      option :name, nil

      # Authentication Request: [REQUIRED]
      # 'openid' は必須.
      # 加えて, OpenID Connect で定義: 'profile', 'email', 'address', 'phone',
      #         および, 認可サーバで定義されたもの.
      option :scope, [:openid]

      # Authentication Request: [REQUIRED]
      # OpenID Connect は、拡張された複数 response_type を使う.
      # See https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
      # ただし, Webアプリでは 'code' 決め打ちでよい.
      # See http://oauth.jp/blog/2015/01/06/oauth2-multiple-response-type/
      option :response_type, "code"

      # Authentication Request: [RECOMMENDED]
      # 次のいずれか;
      #   1. call()メソッドを持つもの. => new_state() から呼び出される.
      #   2. 文字列
      option :state

      # Authentication Request: [NOT RECOMMENDED]
      # 次のいずれか;
      #     'query', 'fragment', 'form_post'
      # 通常は指定不要.
      # See http://qiita.com/TakahikoKawasaki/items/185d34814eb9f7ac7ef3
      # option :response_mode

      # true の場合, 認可リクエストに nonce を付ける
      option :send_nonce, true

      # Authentication Request: [OPTIONAL]
      # [:page, :popup, :touch, :wap]
      option :display, nil

      # Authentication Request: [OPTIONAL]
      # [:none, :login, :consent, :select_account]
      option :prompt, nil

      # Authentication Request: [OPTIONAL]
      option :max_age

      # Authentication Request: [OPTIONAL]
      option :acr_values

      option :hd, nil # what's this?
      option :ux

      # what's this?
      # option :send_scope_to_token_endpoint, true

      # Azure ADは, token_endpoint にも client_id, client_secret を送信しなけ
      # れば失敗する
      option :send_client_secret_to_token_endpoint, false

      # token_endpoint へのリクエスト.
      # default 値: :basic
      option :client_auth_method

      # Any field from user_info to be processed as UID
      option :uid_field, 'sub'

      attr_accessor :access_token

      uid do
        user_info.send(options.uid_field.to_s)
      end

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
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        if !access_token
          {}
        else
          {
            id_token: access_token.id_token,
            token: access_token.access_token,
            refresh_token: access_token.refresh_token,
            expires_in: access_token.expires_in,
            scope: access_token.scope
          }
        end
      end


      def initialize(app, *args, &block)
        if args.last.is_a?(Hash)
          OmniAuth::OpenIDConnect.hash_deep_check(self.class.default_options,
                                                  args.last)
        end
        super
      end


      # @override
      # client_options から OpenIDConnect::Client インスタンスを構築.
      # @return [OpenIDConnect::Client] サーバとのconnection
      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end


      # OpenID Provider Configuration Information を得る.
      # このメソッド内で Config.discover! する.
      #
      # @return [OpenIDConnect::Discovery::Provider::Config::Response] OpenID Provider Configuration Information
      #         <issuer>/.well-known/openid-configuration の内容
      # @exception [OpenIDConnect::Discovery::DiscoveryFailed] 失敗した場合
      #
      # http://openid.net/specs/openid-connect-discovery-1_0.html
      def config
        OmniAuth::OpenIDConnect::Configuration.instance.config(issuer)
      end


      # @override
      # request_phase() と callback_phase() の開始前に呼び出される.
      def setup_phase
        super
        @issuer = if options.issuer
          options.issuer
        else
          client_options.scheme + '://' + client_options.host +
            (client_options.port ? client_options.port.to_s : '')
        end
        unless (uri = URI.parse(@issuer)) &&
          ['http', 'https'].include?(uri.scheme)
          raise ArgumentError, "invalid issuer"
        end

        # OpenID Connect Discovery 1.0 の OpenID Provider Issuer Discovery
        # => 実用的ではない.
        # 引数は identifier 一つだけ.
        #::OpenIDConnect::Discovery::Provider.discover!(resource).issuer

        # これは discover!の前に設定.
        if client_options.scheme == "http"
          WebFinger.url_builder = URI::HTTP
          SWD.url_builder = URI::HTTP
        end

        discover! if options.discovery
      end


      # @override
      def request_phase
        # client() 内で client_options から OpenIDConnect::Client を構築.
        redirect client.authorization_uri(authorize_params)
      end


      # @override
      # See https://github.com/intridea/omniauth-oauth2/
      def callback_phase
        # 'error' 必須
        # 'error_reason' RFC 6749 にはない。Facebookは 'error' に加えて返す.
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'],
                                  request.params['error_description'] ||
                                    request.params['error_reason'],
                                  request.params['error_uri'])
        end
        if session['omniauth.state'] &&
          (request.params['state'].to_s.empty? ||
            request.params['state'] != session.delete('omniauth.state'))
          # RFC 6749 4.1.2: クライアントからの認可リクエストに stateパラメータ
          # が含まれていた場合は, そのまま返ってくる. [REQUIRED]
          raise CallbackError.new(:csrf_detected, "'state' parameter error")
        end

        # request.params["code"] のチェック, id_token の取得もこの中で.
        self.access_token = build_access_token
        # self.access_token = access_token.refresh! if access_token.expired?
        super
      rescue OmniAuth::OpenIDConnect::MissingCodeError => e
        fail!(:missing_code, e)
      rescue CallbackError => e
        fail!(e.error, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      rescue StandardError => e
        fail!(:token_verification_failed, e)
      end


      # @override
      # request_phase() から呼び出される.
      # このメソッド内部で, state値を更新する.
      # @return [Hash] パラメータ.
      def authorize_params
        opts = {
          # OpenIDConnect::Client
          scope: options.scope,
          prompt: options.prompt,
          # Rack::OAuth2::Client
          response_type: options.response_type,

          state: new_state,
          nonce: (new_nonce if options.send_nonce),
        }
        %i[display prompt max_age acr_values hd ux].each do |key|
          opts[key] = options.send(key)
        end

        ['ui_locales', 'id_token_hint', 'login_hint', # OpenID Connect Core 1.0
         # extensions
         'email', 'realm', 'cid', 'chem'].each do |key|
          opts[key.to_sym] = request.params[key] if request.params[key]
        end

        opts.reject { |_k, v| v.nil? }
      end


      def public_key(kid = nil)
        if options.discovery
          # ここで jwks_uri へのアクセスが発生.
          config.jwks # setのままでOK
          # key = config.jwks().select{|k| k["kid"] == kid}.try(:first)
          # JSON::JWK.new(key).to_key
        else
          if options.client_jwk_signing_key
            return OmniAuth::OpenIDConnect.parse_jwk_key(
              options.client_jwk_signing_key, kid)
          elsif options.client_x509_signing_key
            return OmniAuth::OpenIDConnect.parse_x509_key(
              options.client_x509_signing_key, kid)
          end
          raise ArgumentError, "internal error: missing RSA public key"
        end
      end

      private ##############################################

      # @return [String] options.issuer または client_options からつくった issuer
      attr_reader :issuer

      def discover!
        # config() 内で実際に discover! している.
        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
      end

      # @override
      def user_info
        @user_info ||= access_token.userinfo!
      end


      # @override
      # callback_phase() から呼び出される.
      # @return [Rack::OAuth2::AccessToken] アクセストークン
      #         'oauth2'パッケージの OAuth2::AccessToken クラスとは別物.
      def build_access_token
        unless request.params["code"]
          raise OmniAuth::OpenIDConnect::MissingCodeError.new(request.params["error"])
        end

        # これはメソッド呼び出し. See Rack::OAuth2::Client
        client.authorization_code = request.params.delete('code')

        # token_endpoint に対して http request を行う.
        # 仕様では grant_type, code, redirect_uri パラメータ
        opts = {
          # scope: (options.scope if options.send_scope_to_token_endpoint),
          client_auth_method: options.client_auth_method,
        }
        if options.send_client_secret_to_token_endpoint
          opts.merge!(
            client_id: client_options.identifier, # Azure AD only.
            client_secret: client_options.secret
          )
        end
        actoken = client.access_token! opts

        # 鍵を選ぶ。"{ヘッダ部}.{ペイロード部}.{シグネチャ部}" と、ピリオドで
        # 区切られている。ヘッダ部にアルゴリズムが書かれている.
        header = ::JWT.decoded_segments(actoken.id_token, false)[0]
        key = key_or_secret header

        # このなかで署名の検証も行う. => JSON::JWS::VerificationFailed
        id_token = ::OpenIDConnect::ResponseObject::IdToken.decode(
          actoken.id_token, key)
        # こちらは内容の検証.
        id_token.verify!(
          issuer: issuer,
          client_id: client_options.identifier,
          nonce: session.delete('omniauth.nonce'))

        actoken
      end


      def client_options
        options.client_options
      end


      def new_state
        state = nil
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end


      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end


      # @override
      def session
        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end
        super # return @env['rack.session']
      end


      # HMAC-SHA256 の場合は, client_secret を共通鍵とする
      # RSAの場合は, 認証サーバの公開鍵を使う
      def key_or_secret header
        case header['alg'].to_sym
          when :HS256, :HS384, :HS512
            return client_options.secret
          when :RS256, :RS384, :RS512
            return public_key(header['kid'])
          else
            # ES256 : ECDSA using P-256 curve and SHA-256 hash
            raise ArgumentError, "unsupported alg: #{header['alg']}"
        end
      end


      class CallbackError < StandardError
        attr_reader :error
        attr_accessor :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          @error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end # class CallbackError

    end # class OpenIDConnect
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
