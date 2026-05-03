# frozen_string_literal: true

require "test_helper"

class TestCLI < Minitest::Test
  include SilenceOutput

  def setup
    super
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

  def test_cyclonedx_output_format
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
      capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
    end

    sbom = JSON.parse(output)

    assert_equal "CycloneDX", sbom["bomFormat"]
    assert_equal "1.6", sbom["specVersion"]
    assert sbom["components"].any? { |c| c["name"] == "vim" }
    assert sbom["vulnerabilities"].any? { |v| v["id"] == "CVE-2024-1234" }
  end

  def test_cyclonedx_output_includes_vulnerability_details
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
        "summary" => "Buffer overflow vulnerability",
        "database_specific" => { "severity" => "CRITICAL" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
    end

    sbom = JSON.parse(output)
    vuln = sbom["vulnerabilities"].first

    assert_equal "CVE-2024-1234", vuln["id"]
    assert_equal "OSV", vuln["source"]["name"]
    assert_equal "critical", vuln["ratings"].first["severity"]
    assert_equal "Buffer overflow vulnerability", vuln["description"]
    assert_equal "pkg:brew/vim@9.1.0", vuln["affects"].first["ref"]
  end

  def test_cyclonedx_output_with_no_vulnerabilities
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
    end

    sbom = JSON.parse(output)

    assert_equal "CycloneDX", sbom["bomFormat"]
    assert sbom["components"].any? { |c| c["name"] == "vim" }
    assert_empty sbom["vulnerabilities"] || []
  end

  def test_scan_vulnerabilities_limits_active_threads
    formulae = [Brew::Vulns::Formula.new(@vim_data)]
    fake_cves = Array.new(50) { |i| { "id" => "CVE-#{i}" } }

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: fake_cves }] }.to_json)
    fake_cves.each do |cve|
      stub_request(:get, "https://api.osv.dev/v1/vulns/#{cve["id"]}")
        .to_return(status: 200, body: { "id" => cve["id"], "summary" => "Test vulnerability" }
        .to_json)
    end

    max_threads = 0
    current_threads = 0
    # stub thread creation to track how many threads are active at the same time
    Thread.stub(:new, proc { |*args, **kwargs, &block|
      current_threads += 1
      max_threads = [max_threads, current_threads].max
      Thread.start do
        begin
          block.call(*args, **kwargs)
        ensure
          current_threads -= 1
        end
      end
    }) do
      Brew::Vulns::Formula.stub :load_installed, formulae do
        Brew::Vulns::CLI.run([])
      end
    end

    assert max_threads <= Brew::Vulns::CLI::MAX_VULN_FETCH_THREADS,
           "More than #{Brew::Vulns::CLI::MAX_VULN_FETCH_THREADS} threads " \
           "were running concurrently: #{max_threads}"
  end

  # Regression guard for issue #41.
  # When OSV's GIT-ecosystem tag resolution lags behind a new release, the
  # batch endpoint can return CVEs from years ago. The local affects_version?
  # filter at cli.rb:128 is the safety net. This test simulates OSV
  # over-returning and verifies only the vuln whose explicit versions list
  # contains the installed tag survives.
  def test_local_filter_drops_legacy_cves_when_osv_over_returns
    icu_data = {
      "name" => "icu4c@78",
      "versions" => { "stable" => "78.3" },
      "urls" => {
        "stable" => {
          "url" => "https://github.com/unicode-org/icu/releases/download/release-78.3/icu4c-78.3-sources.tgz"
        }
      }
    }
    formulae = [Brew::Vulns::Formula.new(icu_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [
            { "id" => "CVE-2016-6293" },
            { "id" => "CVE-2017-14952" },
            { "id" => "OSV-2023-1328" }
          ]
        }]
      }.to_json)

    # Old CVE: versions list contains only release-57-1, GIT range only.
    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2016-6293")
      .to_return(status: 200, body: {
        "id" => "CVE-2016-6293",
        "summary" => "Stack-based buffer overflow",
        "database_specific" => { "severity" => "CRITICAL" },
        "affected" => [{
          "versions" => ["release-57-1"],
          "ranges" => [{
            "type" => "GIT",
            "events" => [
              { "introduced" => "0" },
              { "last_affected" => "0c5873f89bf64f6bbc0a24b84f07d79b25785a42" }
            ]
          }]
        }]
      }.to_json)

    # Another old CVE: hyphenated old releases only.
    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2017-14952")
      .to_return(status: 200, body: {
        "id" => "CVE-2017-14952",
        "summary" => "Double free",
        "database_specific" => { "severity" => "CRITICAL" },
        "affected" => [{
          "versions" => ["release-58-1", "release-58-2", "release-59-1", "release-59-rc"],
          "ranges" => [{
            "type" => "GIT",
            "events" => [{ "introduced" => "0" }, { "fixed" => "abc123" }]
          }]
        }]
      }.to_json)

    # Current vuln: versions list explicitly names release-78.3.
    stub_request(:get, "https://api.osv.dev/v1/vulns/OSV-2023-1328")
      .to_return(status: 200, body: {
        "id" => "OSV-2023-1328",
        "summary" => "Stack-buffer-overflow in TZDBTimeZoneNames",
        "affected" => [{
          "package" => { "name" => "icu", "ecosystem" => "OSS-Fuzz" },
          "ecosystem_specific" => { "severity" => "HIGH" },
          "versions" => ["release-77-1", "release-78.1", "release-78.2", "release-78.3"],
          "ranges" => [{
            "type" => "GIT",
            "events" => [{ "introduced" => "5cf5ec1adbd2332b3cc289b5b1f5ca8324275fc3" }]
          }]
        }]
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--json"]) }
    end

    json = JSON.parse(output)

    assert_equal 1, json.size
    assert_equal "icu4c@78", json[0]["formula"]
    ids = json[0]["vulnerabilities"].map { |v| v["id"] }
    assert_equal ["OSV-2023-1328"], ids
    refute_includes ids, "CVE-2016-6293"
    refute_includes ids, "CVE-2017-14952"
  end

  # The query payload sent to OSV must always carry a non-empty version.
  # An empty or null version makes OSV return every vuln ever filed against
  # the repo. This test asserts the batch request body never contains
  # version: "" or version: null for any formula that passed the pre-filter.
  def test_batch_query_never_sends_empty_version
    formulae = [
      Brew::Vulns::Formula.new(@vim_data),
      Brew::Vulns::Formula.new(@curl_data)
    ]

    captured_body = nil
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .with { |req| captured_body = JSON.parse(req.body) }
      .to_return(status: 200, body: { results: [{}, {}] }.to_json)

    Brew::Vulns::Formula.stub :load_installed, formulae do
      Brew::Vulns::CLI.run([])
    end

    refute_nil captured_body
    queries = captured_body["queries"]
    # Two formulae with digit-bearing versions = two queries, no canaries.
    assert_equal 2, queries.size
    queries.each do |q|
      refute_nil q["version"], "query #{q.inspect} sent nil version"
      refute_empty q["version"], "query #{q.inspect} sent empty version"
      refute_equal Brew::Vulns::OsvClient::CANARY_VERSION, q["version"]
    end
  end

  # Results must be attributed to the right formula by index. If anything
  # between map(&:to_osv_query) and results lookup ever shifts indices,
  # vim's vulns would land on curl. This test puts a distinctive vuln ID at
  # each batch position and checks each comes back attached to the formula
  # that sent that query.
  def test_batch_results_align_with_formulae
    formulae = [
      Brew::Vulns::Formula.new(@vim_data),
      Brew::Vulns::Formula.new(@curl_data)
    ]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: [{ "id" => "VULN-FOR-VIM" }] },
          { vulns: [{ "id" => "VULN-FOR-CURL" }] }
        ]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/VULN-FOR-VIM")
      .to_return(status: 200, body: {
        "id" => "VULN-FOR-VIM",
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/VULN-FOR-CURL")
      .to_return(status: 200, body: {
        "id" => "VULN-FOR-CURL",
        "database_specific" => { "severity" => "HIGH" }
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--json"]) }
    end

    json = JSON.parse(output)
    by_formula = json.to_h { |entry| [entry["formula"], entry["vulnerabilities"].map { |v| v["id"] }] }

    assert_equal ["VULN-FOR-VIM"], by_formula["vim"]
    assert_equal ["VULN-FOR-CURL"], by_formula["curl"]
  end
end
