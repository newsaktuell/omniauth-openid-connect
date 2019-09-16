# -*- coding:utf-8 -*-
# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    class Error < RuntimeError; end

    # Authorization Response に 'code' [REQUIRED] がない.
    class MissingCodeError < Error; end
  end
end
