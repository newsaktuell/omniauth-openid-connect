require 'singleton'

module OmniAuth
  module OpenIDConnect
    class Configuration
      include Singleton

      def initialize
      end

      def config(issuer)
        ::OpenIDConnect::Discovery::Provider::Config.discover!(issuer)
      end
    end
  end
end