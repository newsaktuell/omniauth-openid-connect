# -*- coding:utf-8 -*-

module OmniAuth
  module OpenIDConnect

    def self.hash_deep_check(this_hash, other_hash)
      raise TypeError if !other_hash.is_a?(Hash)
    
      other_hash.each_pair do |k, v|
        key = k.to_sym
        raise ArgumentError, "unknown key: #{k}" if !this_hash.key?(key)

        # thisがハッシュでないときは、vは単に値としてのハッシュ.
        if this_hash[key].is_a?(Hash) && v.is_a?(Hash)
          hash_deep_check(this_hash[key], v)
        end
      end
    end

  
    # @param [String or IO] key  PEM形式の証明書データ
    # @raise [OpenSSL::X509::CertificateError] 証明書のフォーマットが不正
    def self.parse_x509_key key_or_hash, kid
      if key_or_hash.is_a?(Hash)
        key_or_hash.each do |key, pem|
          if kid == key
            return OpenSSL::X509::Certificate.new(pem).public_key
          end
        end
        raise ArgumentError, "missing kid: #{kid}"
      else
        return OpenSSL::X509::Certificate.new(key_or_hash).public_key
      end
    end


    # @param [String or Hash] key JSON形式の文字列, またはハッシュ.
    def self.parse_jwk_key key_or_hash, kid
      if key_or_hash.is_a?(String)
        json = JSON.parse(key_or_hash)
      elsif key_or_hash.is_a?(Hash)
        json = key_or_hash
      else
        raise TypeError, "key was #{key_or_hash.class}, #{key_or_hash.inspect}"
      end

      if json.has_key?('keys')
        return JSON::JWK::Set.new json['keys']
      else
        return JSON::JWK.new json
      end
    end
  
  end # module OpenIDConnect
end
