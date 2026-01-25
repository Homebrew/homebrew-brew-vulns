# frozen_string_literal: true

require "test_helper"

class TestOsvClient < Minitest::Test
  include SilenceOutput

  def setup
    super
    @client = Brew::Vulns::OsvClient.new
  end

  def test_query_returns_vulnerabilities
    stub_request(:post, "https://api.osv.dev/v1/query")
      .with(body: {
        package: { name: "https://github.com/openssl/openssl", ecosystem: "GIT" },
        version: "openssl-3.0.0"
      }.to_json)
      .to_return(
        status: 200,
        body: { vulns: [{ id: "CVE-2024-1234", summary: "Test vulnerability" }] }.to_json
      )

    vulns = @client.query(repo_url: "https://github.com/openssl/openssl", version: "openssl-3.0.0")

    assert_equal 1, vulns.size
    assert_equal "CVE-2024-1234", vulns.first["id"]
  end

  def test_query_returns_empty_array_when_no_vulnerabilities
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(status: 200, body: {}.to_json)

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal [], vulns
  end

  def test_query_batch_returns_results_for_each_package
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(
        status: 200,
        body: {
          results: [
            { vulns: [{ id: "CVE-2024-1111" }] },
            { vulns: [] },
            { vulns: [{ id: "CVE-2024-2222" }, { id: "CVE-2024-3333" }] }
          ]
        }.to_json
      )

    packages = [
      { repo_url: "https://github.com/a/a", version: "v1" },
      { repo_url: "https://github.com/b/b", version: "v2" },
      { repo_url: "https://github.com/c/c", version: "v3" }
    ]

    results = @client.query_batch(packages)

    assert_equal 3, results.size
    assert_equal 1, results[0].size
    assert_equal 0, results[1].size
    assert_equal 2, results[2].size
  end

  def test_query_batch_returns_empty_array_for_empty_input
    results = @client.query_batch([])
    assert_equal [], results
  end

  def test_raises_api_error_on_http_error
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(status: 500, body: "Internal Server Error")

    assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")
    end
  end

  def test_handles_pagination
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(
        { status: 200, body: { vulns: [{ id: "CVE-1" }], next_page_token: "token123" }.to_json },
        { status: 200, body: { vulns: [{ id: "CVE-2" }] }.to_json }
      )

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal 2, vulns.size
    assert_equal "CVE-1", vulns[0]["id"]
    assert_equal "CVE-2", vulns[1]["id"]
  end

  def test_get_vulnerability_returns_full_data
    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-2024-1234")
      .to_return(
        status: 200,
        body: {
          id: "CVE-2024-1234",
          summary: "Test vulnerability",
          details: "Full details here",
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
        }.to_json
      )

    vuln = @client.get_vulnerability("CVE-2024-1234")

    assert_equal "CVE-2024-1234", vuln["id"]
    assert_equal "Test vulnerability", vuln["summary"]
    assert_equal "Full details here", vuln["details"]
  end

  def test_get_vulnerability_url_encodes_id
    stub_request(:get, "https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz")
      .to_return(status: 200, body: { id: "GHSA-xxxx-yyyy-zzzz" }.to_json)

    vuln = @client.get_vulnerability("GHSA-xxxx-yyyy-zzzz")

    assert_equal "GHSA-xxxx-yyyy-zzzz", vuln["id"]
  end

  def test_get_vulnerability_raises_on_not_found
    stub_request(:get, "https://api.osv.dev/v1/vulns/CVE-0000-0000")
      .to_return(status: 404, body: "Not found")

    assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.get_vulnerability("CVE-0000-0000")
    end
  end

  def test_raises_api_error_on_timeout_after_retries
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_timeout

    error = assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")
    end

    assert_match(/after 3 attempts/, error.message)
  end

  def test_raises_api_error_on_connection_refused_after_retries
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_raise(Errno::ECONNREFUSED)

    error = assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")
    end

    assert_match(/after 3 attempts/, error.message)
  end

  def test_retries_on_timeout_then_succeeds
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_timeout.then
      .to_return(status: 200, body: { vulns: [{ id: "CVE-2024-1234" }] }.to_json)

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal 1, vulns.size
    assert_equal "CVE-2024-1234", vulns.first["id"]
  end

  def test_retries_on_connection_error_then_succeeds
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_raise(Errno::ECONNREFUSED).then
      .to_return(status: 200, body: { vulns: [] }.to_json)

    vulns = @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_equal [], vulns
  end
end
