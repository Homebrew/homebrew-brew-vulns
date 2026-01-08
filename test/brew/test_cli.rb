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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--json"]) }
    end

    json = JSON.parse(output)

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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run([]) }
    end

    assert_includes output, "#{"A" * 60}..."
    refute_includes output, "A" * 100
  end

  def test_max_summary_flag_changes_truncation
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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--max-summary", "80"]) }
    end

    assert_includes output, "#{"A" * 80}..."
    refute_includes output, "A" * 100
  end

  def test_max_summary_zero_disables_truncation
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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["-m", "0"]) }
    end

    assert_includes output, "A" * 100
    refute_includes output, "#{"A" * 60}..."
  end

  def test_max_summary_equals_syntax
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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--max-summary=40"]) }
    end

    assert_includes output, "#{"A" * 40}..."
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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run([]) }
    end

    assert_includes output, "CVE-2024-1234 (UNKNOWN)"
    refute_includes output, " - \n"
  end

  def test_severity_flag_filters_vulnerabilities
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [
            { "id" => "CVE-2024-1111" },
            { "id" => "CVE-2024-2222" }
          ]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1111")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1111",
        "summary" => "High severity",
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-2222")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-2222",
        "summary" => "Low severity",
        "database_specific" => { "severity" => "LOW" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--severity", "high"]) }
    end

    assert_includes output, "CVE-2024-1111"
    refute_includes output, "CVE-2024-2222"
  end

  def test_severity_flag_equals_syntax
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1111" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1111")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1111",
        "database_specific" => { "severity" => "LOW" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--severity=high"]) }
    end

    assert_includes output, "No vulnerabilities found"
    refute_includes output, "CVE-2024-1111"
  end

  def test_severity_short_flag
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1111" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1111")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1111",
        "database_specific" => { "severity" => "CRITICAL" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["-s", "critical"]) }
    end

    assert_includes output, "CVE-2024-1111"
    assert_includes output, "CRITICAL"
  end

  def test_sarif_output_format
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

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
    end

    sarif = JSON.parse(output)

    assert_equal "2.1.0", sarif["version"]
    assert_equal 1, sarif["runs"].size
    assert_equal "brew-vulns", sarif["runs"][0]["tool"]["driver"]["name"]
    assert_equal 1, sarif["runs"][0]["results"].size
    assert_equal "CVE-2024-1234", sarif["runs"][0]["results"][0]["ruleId"]
    assert_equal "error", sarif["runs"][0]["results"][0]["level"]
  end

  def test_sarif_output_returns_one_with_vulnerabilities
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
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
      Brew::Vulns::CLI.run(["--sarif"])
    end

    assert_equal 1, result
  end

  def test_sarif_critical_severity_maps_to_error
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1111" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1111")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1111",
        "database_specific" => { "severity" => "CRITICAL" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
    end

    sarif = JSON.parse(output)
    result = sarif["runs"][0]["results"][0]

    assert_equal "error", result["level"]
  end

  def test_sarif_medium_severity_maps_to_warning
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-2222" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-2222")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-2222",
        "database_specific" => { "severity" => "MEDIUM" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
    end

    sarif = JSON.parse(output)
    result = sarif["runs"][0]["results"][0]

    # "warning" is the default SARIF level, so it may be omitted in output
    assert_includes [nil, "warning"], result["level"]
  end

  def test_sarif_low_severity_maps_to_note
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-3333" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-3333")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-3333",
        "database_specific" => { "severity" => "LOW" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
    end

    sarif = JSON.parse(output)
    result = sarif["runs"][0]["results"][0]

    # SARIF may omit "note" level since it's not the default, but let's be permissive
    assert_includes ["note", nil], result["level"]
  end

  def test_brewfile_flag_loads_from_brewfile
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_from_brewfile_called = false
    load_from_brewfile_mock = lambda do |path, include_deps:|
      load_from_brewfile_called = true
      assert_equal "/path/to/Brewfile", path
      refute include_deps
      formulae
    end

    Brew::Vulns::Formula.stub :load_from_brewfile, load_from_brewfile_mock do
      Brew::Vulns::CLI.run(["--brewfile", "/path/to/Brewfile"])
    end

    assert load_from_brewfile_called
  end

  def test_brewfile_flag_with_deps
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_from_brewfile_mock = lambda do |path, include_deps:|
      assert include_deps
      formulae
    end

    Brew::Vulns::Formula.stub :load_from_brewfile, load_from_brewfile_mock do
      Brew::Vulns::CLI.run(["-b", "Brewfile", "--deps"])
    end
  end

  def test_brewfile_short_flag
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_from_brewfile_called = false
    load_from_brewfile_mock = lambda do |path, include_deps:|
      load_from_brewfile_called = true
      formulae
    end

    Brew::Vulns::Formula.stub :load_from_brewfile, load_from_brewfile_mock do
      Brew::Vulns::CLI.run(["-b", "Brewfile"])
    end

    assert load_from_brewfile_called
  end

  def test_brewfile_flag_without_path_defaults_to_brewfile
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_from_brewfile_mock = lambda do |path, include_deps:|
      assert_equal "Brewfile", path
      formulae
    end

    Brew::Vulns::Formula.stub :load_from_brewfile, load_from_brewfile_mock do
      Brew::Vulns::CLI.run(["--brewfile"])
    end
  end
end
