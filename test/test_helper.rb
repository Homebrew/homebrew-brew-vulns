# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  add_filter "/test/"
end

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "brew/vulns"

require "minitest/autorun"
require "minitest/mock"
require "webmock/minitest"

def capture_stdout
  output = StringIO.new
  original_stdout = $stdout
  $stdout = output
  yield
  output.string
ensure
  $stdout = original_stdout
end

def capture_stderr
  output = StringIO.new
  original_stderr = $stderr
  $stderr = output
  yield
  output.string
ensure
  $stderr = original_stderr
end

module SilenceOutput
  def setup
    super
    @original_stdout = $stdout
    @original_stderr = $stderr
    $stdout = StringIO.new
    $stderr = StringIO.new
  end

  def teardown
    $stdout = @original_stdout
    $stderr = @original_stderr
    super
  end
end
