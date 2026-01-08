# frozen_string_literal: true

require "test_helper"

class TestCLI < Minitest::Test
  def setup
    @vim_data = {
      "name" => "vim",
      "versions" => { "stable" => "9.1.0" },
      "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
    }
    @curl_data = {
      "name" => "curl",
      "versions" => { "stable" => "8.5.0" },
      "urls" => { "stable" => { "url" => "https://github.com/curl/curl/archive/refs/tags/curl-8_5_0.tar.gz" } }
    }
  end

  def test_help_flag_returns_zero
    result = Brew::Vulns::CLI.run(["--help"])
    assert_equal 0, result
  end

  def test_help_short_flag_returns_zero
    result = Brew::Vulns::CLI.run(["-h"])
    assert_equal 0, result
  end

  def test_no_formulae_returns_zero
    Brew::Vulns::Formula.stub :load_installed, [] do
      result = Brew::Vulns::CLI.run([])
      assert_equal 0, result
    end
  end

  def test_no_vulnerabilities_returns_zero
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    Brew::Vulns::Formula.stub :load_installed, formulae do
      result = Brew::Vulns::CLI.run([])
      assert_equal 0, result
    end
  end

  def test_vulnerabilities_found_returns_one
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1234",
        "summary" => "Test vuln",
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    Brew::Vulns::Formula.stub :load_installed, formulae do
      result = Brew::Vulns::CLI.run([])
      assert_equal 1, result
    end
  end

  def test_json_output_format
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1234",
        "summary" => "Test vulnerability",
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    output = StringIO.new
    original_stdout = $stdout
    $stdout = output

    Brew::Vulns::Formula.stub :load_installed, formulae do
      Brew::Vulns::CLI.run(["--json"])
    end

    $stdout = original_stdout
    json = JSON.parse(output.string)

    assert_equal 1, json.size
    assert_equal "vim", json[0]["formula"]
    assert_equal "CVE-2024-1234", json[0]["vulnerabilities"][0]["id"]
    assert_equal "HIGH", json[0]["vulnerabilities"][0]["severity"]
  end

  def test_skips_unsupported_source_urls
    unsupported_data = {
      "name" => "example",
      "versions" => { "stable" => "1.0.0" },
      "urls" => { "stable" => { "url" => "https://example.com/source.tar.gz" } }
    }
    formulae = [Brew::Vulns::Formula.new(unsupported_data)]

    Brew::Vulns::Formula.stub :load_installed, formulae do
      result = Brew::Vulns::CLI.run([])
      assert_equal 0, result
    end
  end

  def test_api_error_returns_one
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 500, body: "Internal Server Error")

    Brew::Vulns::Formula.stub :load_installed, formulae do
      result = Brew::Vulns::CLI.run([])
      assert_equal 1, result
    end
  end

  def test_filters_by_formula_name
    vim = Brew::Vulns::Formula.new(@vim_data)
    curl = Brew::Vulns::Formula.new(@curl_data)

    load_mock = lambda do |filter|
      filter == "vim" ? [vim] : [vim, curl]
    end

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    Brew::Vulns::Formula.stub :load_installed, load_mock do
      result = Brew::Vulns::CLI.run(["vim"])
      assert_equal 0, result
    end
  end

  def test_includes_deps_flag
    vim = Brew::Vulns::Formula.new(@vim_data)

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_with_deps_called = false
    load_with_deps_mock = lambda do |filter|
      load_with_deps_called = true
      assert_equal "vim", filter
      [vim]
    end

    Brew::Vulns::Formula.stub :load_with_dependencies, load_with_deps_mock do
      Brew::Vulns::CLI.run(["vim", "--deps"])
    end

    assert load_with_deps_called
  end

  def test_output_truncates_long_summaries
    formulae = [Brew::Vulns::Formula.new(@vim_data)]
    long_summary = "A" * 100

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1234",
        "summary" => long_summary
      }.to_json)

    output = StringIO.new
    original_stdout = $stdout
    $stdout = output

    Brew::Vulns::Formula.stub :load_installed, formulae do
      Brew::Vulns::CLI.run([])
    end

    $stdout = original_stdout

    assert_includes output.string, "#{"A" * 60}..."
    refute_includes output.string, "A" * 100
  end

  def test_output_handles_nil_summary
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: { "id" => "CVE-2024-1234" }.to_json)

    output = StringIO.new
    original_stdout = $stdout
    $stdout = output

    Brew::Vulns::Formula.stub :load_installed, formulae do
      Brew::Vulns::CLI.run([])
    end

    $stdout = original_stdout

    assert_includes output.string, "CVE-2024-1234 (UNKNOWN)"
    refute_includes output.string, " - \n"
  end
end
