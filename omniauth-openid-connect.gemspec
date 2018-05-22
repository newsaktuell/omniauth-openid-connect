# -*- coding:utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/openid_connect/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-openid-connect"
  spec.version       = OmniAuth::OpenIDConnect::VERSION
  spec.authors       = ["Hisashi Horikawa", "Paul Scarrone","John Bohn"]
  spec.email         = ["hisashi.horikawa@gmail.com", "paul.scarrone@gmail.com","jjbohn@gmail.com"]
  spec.summary       = %q{OpenID Connect Strategy MK2 for OmniAuth}
  spec.description   = %q{OpenID Connect Strategy MK2 for OmniAuth which is fully compliant with devise and rails and currently maintained. Derived from jjbohn's work which is not actively maintained}
  spec.homepage      = "https://github.com/hhorikawa/omniauth-openid-connect"
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.2'
  
  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

=begin
  このパッケージは, これらと同時に使われるのが考えられる;
    - omniauth-facebook
    - omniauth-paypal-oauth2   # omniauth-paypal は古い.
      https://rubygems.org/gems/omniauth-paypal-oauth2/

    omniauth-facebook (4.0.0)
      omniauth-oauth2 (~> 1.2)
    omniauth-oauth2 (1.4.0)
      oauth2 (~> 1.0)
      omniauth (~> 1.2)
    openid_connect (1.1.3)
      activemodel
      attr_required (>= 1.0.0)
      json (>= 1.4.3)
      json-jwt (>= 1.5.0)
      rack-oauth2 (>= 1.6.1)
      swd (>= 1.0.0)
      tzinfo
      validate_email
      validate_url
      webfinger (>= 1.0.1)
    omniauth (1.6.1)
      hashie (>= 3.4.6, < 3.6.0)
      rack (>= 1.6.2, < 3)
=end
  
  # symbolize_keys() 
  spec.add_dependency 'activesupport', '>= 4.2' 
  spec.add_dependency 'omniauth', '~> 1.6'
  spec.add_dependency 'openid_connect', '~> 1.1'

  # A replacement for the URI implementation that is part of Ruby's standard
  # library.
  # LICENSE: APACHE-2.0 
  #spec.add_dependency 'addressable', '~> 2.5'   # 実際には使っていない
  
  # jwt 2.0.0 が出ているが, oauth2 1.4.0 depends on jwt ~> 1.0
  # 'jwt' と 'json-jwt' があるが, 'jwt' が多数派.
  spec.add_dependency 'jwt', '~> 1.5'

  spec.add_development_dependency "bundler", "~> 1.5"
  # Ruby 2.2からバンドルされる. gem依存不要
  #spec.add_development_dependency "minitest"
  spec.add_development_dependency "mocha"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-minitest"
  spec.add_development_dependency "guard-bundler"
  spec.add_development_dependency "rake"
  # v0.15.0 が出てる
  spec.add_development_dependency "simplecov", '~> 0.13.0'
  spec.add_development_dependency "pry"
  # 'coveralls' 0.8.21 depends on simplecov ~> 0.14.1
  #spec.add_development_dependency "coveralls"
  spec.add_development_dependency "faker"
end
