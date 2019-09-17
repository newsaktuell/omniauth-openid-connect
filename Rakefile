# -*- coding: utf-8 -*-

require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new do |t|
  # デフォルトで'lib'は入っている.
  #t.libs << 'lib/omniauth-openid-connect'
  t.test_files = FileList['test/**/*_test.rb']
  t.verbose = true
end
desc "Run tests"

# 単に rake コマンドでテスト実行.
#task default: [:test]
