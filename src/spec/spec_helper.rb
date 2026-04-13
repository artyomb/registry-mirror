# frozen_string_literal: true
$VERBOSE = nil

require 'rspec-benchmark'
require 'rack/test'
require 'async/rspec'
require 'rack/builder'
require 'fileutils'
require 'tmpdir'

require 'simplecov'
SimpleCov.start

ENV['DB_URL'] = 'sqlite::memory:'
TEST_CACHE_DIR = Dir.mktmpdir('registry-mirror-test-cache')
ENV['CACHE_DIR'] = TEST_CACHE_DIR

at_exit do
  FileUtils.remove_entry(TEST_CACHE_DIR) if File.directory?(TEST_CACHE_DIR)
end

$app = Rack::Builder.parse_file(File.expand_path 'config.ru')

module Rack::Test::JHelpers
  def app = $app
end

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include Rack::Test::JHelpers
  config.include RSpec::Benchmark::Matchers
  config.include_context Async::RSpec::Reactor

  config.before(:each) do
    header 'Host', 'localhost'
  end
end
