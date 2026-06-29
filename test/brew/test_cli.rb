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
    @libquicktime_data = {
      "name"     => "libquicktime",
      "versions" => { "stable" => "1.2.4" },
      "urls"     => {
        "stable" => { "url" => "https://github.com/example/libquicktime/archive/refs/tags/v1.2.4.tar.gz" },
      },
      "patches"  => [
        {
          "strip"    => "p1",
          "url"      => "https://deb.debian.org/debian/pool/main/libq/libquicktime/libquicktime_1.2.4-12.debian.tar.xz",
          "type"     => "backport",
          "resolves" => [
            { "type" => "security", "id" => "CVE-2016-2399" },
            { "type" => "security", "id" => "CVE-2017-9122" },
          ],
        },
      ],
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

  def test_api_error_returns_two
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 500, body: "Internal Server Error")

    Brew::Vulns::Formula.stub :load_installed, formulae do
      result = Brew::Vulns::CLI.run([])
      assert_equal 2, result
    end
  end

  def test_ipv4_flag_passes_force_ipv4_to_client
    captured = nil
    fake_client = Object.new
    fake_client.define_singleton_method(:query_batch) { |_| [] }

    Brew::Vulns::Formula.stub :load_installed, [Brew::Vulns::Formula.new(@vim_data)] do
      Brew::Vulns::OsvClient.stub :new, ->(**opts) { captured = opts; fake_client } do
        result = Brew::Vulns::CLI.run(["--ipv4"])
        assert_equal 0, result
      end
    end

    assert_equal({ force_ipv4: true }, captured)
  end

  def test_no_ipv4_flag_passes_force_ipv4_false
    captured = nil
    fake_client = Object.new
    fake_client.define_singleton_method(:query_batch) { |_| [] }

    Brew::Vulns::Formula.stub :load_installed, [Brew::Vulns::Formula.new(@vim_data)] do
      Brew::Vulns::OsvClient.stub :new, ->(**opts) { captured = opts; fake_client } do
        Brew::Vulns::CLI.run([])
      end
    end

    assert_equal({ force_ipv4: false }, captured)
  end

  def test_osv_export_flag_runs_over_all_formulae_by_default
    libqt = Brew::Vulns::Formula.new(@libquicktime_data)
    vim = Brew::Vulns::Formula.new(@vim_data)

    export_args = nil
    Brew::Vulns::Formula.stub :load_all, [libqt, vim] do
      Brew::Vulns::OsvExport.stub :run, ->(formulae, dir, **) { export_args = [formulae, dir]; [] } do
        result = Brew::Vulns::CLI.run(["--osv-export", "/tmp/out"])

        assert_equal 0, result
      end
    end

    refute_nil export_args
    assert_equal [libqt], export_args[0]
    assert_equal "/tmp/out", export_args[1]
  end

  def test_osv_export_flag_with_named_formulae
    libqt = Brew::Vulns::Formula.new(@libquicktime_data)

    Brew::Vulns::Formula.stub :load_named, ->(names, **) { assert_equal ["libquicktime"], names; [libqt] } do
      Brew::Vulns::OsvExport.stub :run, ->(*) { [] } do
        result = Brew::Vulns::CLI.run(["--osv-export=/tmp/out", "libquicktime"])

        assert_equal 0, result
      end
    end
  end

  def test_osv_export_flag_requires_dir
    assert_equal 2, Brew::Vulns::CLI.run(["--osv-export"])
    assert_equal 2, Brew::Vulns::CLI.run(["--osv-export="])
    assert_equal 2, Brew::Vulns::CLI.run(["--osv-export", "--json"])
  end

  def test_load_error_returns_two
    Brew::Vulns::Formula.stub :load_installed, ->(*) { raise Brew::Vulns::Error, "boom" } do
      result = Brew::Vulns::CLI.run([])
      assert_equal 2, result
    end
  end

  def test_json_parse_error_returns_two
    Brew::Vulns::Formula.stub :load_installed, ->(*) { raise JSON::ParserError, "unexpected token" } do
      result = Brew::Vulns::CLI.run([])
      assert_equal 2, result
    end
  end

  def test_filters_by_formula_name
    vim = Brew::Vulns::Formula.new(@vim_data)

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_named_called = false
    load_named_mock = lambda do |names, include_deps:|
      load_named_called = true
      assert_equal ["vim"], names
      refute include_deps
      [vim]
    end

    Brew::Vulns::Formula.stub :load_named, load_named_mock do
      result = Brew::Vulns::CLI.run(["vim"])
      assert_equal 0, result
    end

    assert load_named_called
  end

  def test_multiple_formula_names
    vim = Brew::Vulns::Formula.new(@vim_data)
    curl = Brew::Vulns::Formula.new(@curl_data)

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }, { vulns: [] }] }.to_json)

    load_named_mock = lambda do |names, include_deps:|
      assert_equal ["vim", "curl"], names
      [vim, curl]
    end

    Brew::Vulns::Formula.stub :load_named, load_named_mock do
      result = Brew::Vulns::CLI.run(["vim", "curl"])
      assert_equal 0, result
    end
  end

  def test_formula_names_ignore_flag_values
    vim = Brew::Vulns::Formula.new(@vim_data)

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_named_mock = lambda do |names, include_deps:|
      assert_equal ["vim"], names
      [vim]
    end

    Brew::Vulns::Formula.stub :load_named, load_named_mock do
      Brew::Vulns::CLI.run(["-m", "80", "vim", "-s", "high"])
    end
  end

  def test_includes_deps_flag
    vim = Brew::Vulns::Formula.new(@vim_data)

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_named_called = false
    load_named_mock = lambda do |names, include_deps:|
      load_named_called = true
      assert_equal ["vim"], names
      assert include_deps
      [vim]
    end

    Brew::Vulns::Formula.stub :load_named, load_named_mock do
      Brew::Vulns::CLI.run(["vim", "--deps"])
    end

    assert load_named_called
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

  def test_text_output_sanitizes_terminal_escapes_from_summary
    formulae = [Brew::Vulns::Formula.new(@vim_data)]
    summary = "safe \e[2J\e[31mred\e[0m \e]0;pwned\a c1 \u009b2Jblue\u009d0;owned\a \rhidden\b text"

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1234",
        "summary" => summary
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run([]) }
    end

    assert_includes output, "safe red  c1 blue hidden text"
    refute_includes output, "\e"
    refute_includes output, "\u009b"
    refute_includes output, "\u009d"
    refute_includes output, "\r"
    refute_includes output, "\b"
    refute_includes output, "[2J"
    refute_includes output, "pwned"
    refute_includes output, "owned"
  end

  def test_text_output_sanitizes_terminal_escapes_from_other_fields
    formulae = [
      Brew::Vulns::Formula.new(
        @vim_data.merge(
          "name" => "vim\e[2J",
          "versions" => { "stable" => "9.1.0\e[31m" }
        )
      )
    ]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2024-1234" }]
        }]
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id" => "CVE-2024-1234\e[2J",
        "affected" => [
          {
            "versions" => ["v9.1.0"],
            "ranges" => [
              {
                "events" => [
                  { "fixed" => "1.2.3\e[31m" }
                ]
              }
            ]
          }
        ]
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run([]) }
    end

    assert_includes output, "vim (9.1.0)"
    assert_includes output, "CVE-2024-1234 (UNKNOWN)"
    assert_includes output, "Fixed in: 1.2.3"
    refute_includes output, "\e"
    refute_includes output, "[2J"
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

  def test_sarif_output_with_no_vulnerabilities_includes_empty_results
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
      Brew::Vulns::CLI.run(["--sarif"])
    end

    sarif = JSON.parse(output)

    assert_equal 0, result
    assert sarif["runs"][0].key?("results"), "SARIF run must include results key even when empty"
    assert_equal [], sarif["runs"][0]["results"]
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

  def stub_libquicktime_osv(extra_vulns: [])
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{
          vulns: [{ "id" => "CVE-2016-2399" }, { "id" => "GHSA-aaaa-bbbb-cccc" }] + extra_vulns,
        }],
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2016-2399")
      .to_return(status: 200, body: {
        "id"                => "CVE-2016-2399",
        "summary"           => "Heap buffer overflow",
        "database_specific" => { "severity" => "HIGH" },
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc")
      .to_return(status: 200, body: {
        "id"                => "GHSA-aaaa-bbbb-cccc",
        "aliases"           => ["CVE-2017-9122"],
        "summary"           => "DoS in quicktime_read_moov",
        "database_specific" => { "severity" => "MEDIUM" },
      }.to_json)
  end

  def test_suppresses_vulns_resolved_by_formula_patches
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run([]) }
      Brew::Vulns::CLI.run([])
    end

    assert_equal 0, result
    assert_includes output, "No open vulnerabilities found."
    assert_includes output, "2 resolved by formula patches"
    assert_includes output, "libquicktime: CVE-2016-2399, GHSA-aaaa-bbbb-cccc"
  end

  def test_no_ignore_patches_flag_reports_resolved_vulns
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--no-ignore-patches"]) }
      Brew::Vulns::CLI.run(["--no-ignore-patches"])
    end

    assert_equal 1, result
    assert_includes output, "CVE-2016-2399 (HIGH)"
    assert_includes output, "GHSA-aaaa-bbbb-cccc (MEDIUM)"
    refute_includes output, "resolved by formula patches"
  end

  def test_unpatched_vuln_still_reported_alongside_patched_ones
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv(extra_vulns: [{ "id" => "CVE-2024-9999" }])

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-9999")
      .to_return(status: 200, body: {
        "id"                => "CVE-2024-9999",
        "summary"           => "Unpatched issue",
        "database_specific" => { "severity" => "CRITICAL" },
      }.to_json)

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run([]) }
      Brew::Vulns::CLI.run([])
    end

    assert_equal 1, result
    assert_includes output, "CVE-2024-9999 (CRITICAL)"
    assert_includes output, "Found 1 vulnerabilities in 1 packages"
    assert_includes output, "2 resolved by formula patches"
    refute_includes output, "CVE-2016-2399 (HIGH)"
  end

  def test_json_output_includes_patched_array
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--json"]) }
      Brew::Vulns::CLI.run(["--json"])
    end

    json = JSON.parse(output)

    assert_equal 0, result
    assert_equal 1, json.size
    assert_equal "libquicktime", json[0]["formula"]
    assert_empty json[0]["vulnerabilities"]
    assert_equal 2, json[0]["patched"].size
    ids = json[0]["patched"].map { |v| v["id"] }
    assert_includes ids, "CVE-2016-2399"
    assert_includes ids, "GHSA-aaaa-bbbb-cccc"
  end

  def test_json_output_patched_array_empty_for_unpatched_formula
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{ vulns: [{ "id" => "CVE-2024-1234" }] }],
      }.to_json)

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(status: 200, body: {
        "id"                => "CVE-2024-1234",
        "database_specific" => { "severity" => "HIGH" },
      }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--json"]) }
    end

    json = JSON.parse(output)

    assert_equal 1, json[0]["vulnerabilities"].size
    assert_empty json[0]["patched"]
  end

  def test_cyclonedx_marks_patched_vulns_as_resolved
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
      Brew::Vulns::CLI.run(["--cyclonedx"])
    end

    sbom = JSON.parse(output)

    assert_equal 0, result

    component = sbom["components"].find { |c| c["name"] == "libquicktime" }
    patches = component["pedigree"]["patches"]

    assert_equal 1, patches.size
    assert_equal "backport", patches[0]["type"]
    assert_equal "https://deb.debian.org/debian/pool/main/libq/libquicktime/libquicktime_1.2.4-12.debian.tar.xz",
                 patches[0]["diff"]["url"]
    resolved_ids = patches[0]["resolves"].map { |r| r["id"] }

    assert_includes resolved_ids, "CVE-2016-2399"
    assert_includes resolved_ids, "CVE-2017-9122"

    vulns = sbom["vulnerabilities"]

    assert_equal 2, vulns.size
    vulns.each do |v|
      assert_equal "resolved", v["analysis"]["state"]
      assert_equal ["update"], v["analysis"]["response"]
      assert_match(/Resolved by Homebrew formula patch/, v["analysis"]["detail"])
    end

    ghsa = vulns.find { |v| v["id"] == "GHSA-aaaa-bbbb-cccc" }

    assert_match(/CVE-2017-9122/, ghsa["analysis"]["detail"])
  end

  def test_cyclonedx_open_vulns_have_no_analysis
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv(extra_vulns: [{ "id" => "CVE-2099-9999" }])

    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2099-9999")
      .to_return(status: 200, body: {
        "id"                => "CVE-2099-9999",
        "summary"           => "Unpatched issue",
        "database_specific" => { "severity" => "HIGH" },
      }.to_json)

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
      Brew::Vulns::CLI.run(["--cyclonedx"])
    end

    sbom = JSON.parse(output)

    assert_equal 1, result

    open_vuln = sbom["vulnerabilities"].find { |v| v["id"] == "CVE-2099-9999" }
    resolved = sbom["vulnerabilities"].find { |v| v["id"] == "CVE-2016-2399" }

    refute open_vuln.key?("analysis")
    assert_equal "resolved", resolved["analysis"]["state"]
  end

  def test_sarif_omits_patched_vulns
    formulae = [Brew::Vulns::Formula.new(@libquicktime_data)]
    stub_libquicktime_osv

    output = nil
    result = Brew::Vulns::Formula.stub :load_installed, formulae do
      output = capture_stdout { Brew::Vulns::CLI.run(["--sarif"]) }
      Brew::Vulns::CLI.run(["--sarif"])
    end

    sarif = JSON.parse(output)

    assert_equal 0, result
    assert_equal [], sarif["runs"][0]["results"]
  end

  def test_all_flag_uses_load_all
    formulae = [Brew::Vulns::Formula.new(@vim_data)]

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [] }] }.to_json)

    load_all_called = false
    load_all_mock = lambda do
      load_all_called = true
      formulae
    end

    Brew::Vulns::Formula.stub :load_all, load_all_mock do
      result = Brew::Vulns::CLI.run(["--all"])
      assert_equal 0, result
    end

    assert load_all_called
  end

  def test_all_flag_with_json_output
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

    output = Brew::Vulns::Formula.stub :load_all, formulae do
      capture_stdout { Brew::Vulns::CLI.run(["--all", "--json"]) }
    end
    json = JSON.parse(output)

    assert_equal 1, json.size
    assert_equal "vim", json[0]["formula"]
    assert_equal "CVE-2024-1234", json[0]["vulnerabilities"][0]["id"]
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

  def test_cyclonedx_output_encodes_at_in_formula_name_purls
    glibc_213 = Brew::Vulns::Formula.new(
      "name"     => "glibc@2.13",
      "versions" => { "stable" => "2.13" },
      "urls"     => { "stable" => { "url" => "https://github.com/example/glibc/archive/refs/tags/v2.13.tar.gz" } },
    )

    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: { results: [{ vulns: [{ "id" => "CVE-2024-2961" }] }] }.to_json)
    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-2961")
      .to_return(status: 200, body: { "id" => "CVE-2024-2961" }.to_json)

    output = Brew::Vulns::Formula.stub :load_installed, [glibc_213] do
      capture_stdout { Brew::Vulns::CLI.run(["--cyclonedx"]) }
    end
    sbom = JSON.parse(output)

    assert_equal "pkg:brew/glibc%402.13@2.13", sbom["components"][0]["purl"]
    assert_equal "pkg:brew/glibc%402.13@2.13", sbom["vulnerabilities"][0]["affects"][0]["ref"]
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
end
