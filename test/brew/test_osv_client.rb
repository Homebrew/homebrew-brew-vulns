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

  def test_sets_user_agent_header
    stub_request(:post, "https://api.osv.dev/v1/query")
      .with(
        headers: {
          "User-Agent" => %r{\Abrew-vulns/\d+\.\d+\.\d+ \(\+https://github\.com/Homebrew/homebrew-brew-vulns\)\z}
        }
      )
      .to_return(status: 200, body: { vulns: [] }.to_json)

    @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")

    assert_requested :post, "https://api.osv.dev/v1/query"
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

  def test_query_batch_adds_canary_only_for_digit_free_versions
    captured = nil
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .with { |req| captured = JSON.parse(req.body) }
      .to_return(status: 200, body: { results: [{}, {}, {}] }.to_json)

    packages = [
      { repo_url: "https://github.com/a/a", version: "v1.0" },
      { repo_url: "https://github.com/b/b", version: "HEAD" }
    ]
    @client.query_batch(packages)

    # Only the digit-free version gets a paired canary query.
    queries = captured["queries"]
    assert_equal 3, queries.size
    assert_equal "v1.0", queries[0]["version"]
    assert_equal "HEAD", queries[1]["version"]
    assert_equal Brew::Vulns::OsvClient::CANARY_VERSION, queries[2]["version"]
    assert_equal "https://github.com/a/a", queries[0]["package"]["name"]
    assert_equal "https://github.com/b/b", queries[1]["package"]["name"]
    assert_equal "https://github.com/b/b", queries[2]["package"]["name"]
  end

  def test_query_batch_skips_when_real_matches_canary
    # Identical non-empty result sets at real and canary positions means OSV
    # resolved both to the same fallback. The package should come back empty.
    fallback = [{ id: "CVE-2017-1111" }, { id: "CVE-2017-2222" }]
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: fallback },
          { vulns: fallback }
        ]
      }.to_json)

    packages = [{ repo_url: "https://github.com/a/a", version: "HEAD", name: "a" }]

    err = capture_stderr { @results = @client.query_batch(packages) }

    assert_equal [[]], @results
    assert_match(/OSV could not resolve a tag "HEAD"/, err)
  end

  def test_query_batch_never_skips_digit_bearing_version
    # A vuln with introduced:0 and no fix affects every commit. If we sent a
    # canary for a normal digit-bearing version, real and canary would match
    # and we'd wrongly suppress it. Digit-bearing versions must not be gated.
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [{ vulns: [{ id: "CVE-2024-OPEN" }] }]
      }.to_json)

    packages = [{ repo_url: "https://github.com/a/a", version: "v9.9.9", name: "a" }]

    err = capture_stderr { @results = @client.query_batch(packages) }

    assert_equal "CVE-2024-OPEN", @results[0][0]["id"]
    assert_empty err
    assert_requested(:post, "https://api.osv.dev/v1/querybatch") do |req|
      JSON.parse(req.body)["queries"].size == 1
    end
  end

  def test_query_batch_keeps_results_when_real_differs_from_canary
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: [{ id: "OSV-2023-1328" }] },
          { vulns: [{ id: "CVE-2017-1111" }, { id: "CVE-2017-2222" }] }
        ]
      }.to_json)

    packages = [{ repo_url: "https://github.com/a/a", version: "main", name: "icu" }]

    err = capture_stderr { @results = @client.query_batch(packages) }

    assert_equal 1, @results[0].size
    assert_equal "OSV-2023-1328", @results[0][0]["id"]
    assert_empty err
  end

  def test_query_batch_keeps_results_when_canary_is_empty
    # An empty canary tells us nothing. Even if real is also empty, that is
    # the normal "no vulns" case, not a fallback signal.
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: [{ id: "CVE-2024-1234" }] },
          {}
        ]
      }.to_json)

    packages = [{ repo_url: "https://github.com/a/a", version: "main", name: "a" }]
    results = @client.query_batch(packages)

    assert_equal 1, results[0].size
  end

  def test_query_batch_compares_id_sets_not_order
    # OSV does not guarantee result order. Sort before comparing.
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: [{ id: "CVE-A" }, { id: "CVE-B" }] },
          { vulns: [{ id: "CVE-B" }, { id: "CVE-A" }] }
        ]
      }.to_json)

    packages = [{ repo_url: "https://github.com/a/a", version: "main", name: "a" }]
    results = @client.query_batch(packages)

    assert_equal [], results[0]
  end

  def test_query_batch_canary_only_affects_matching_package
    # Three packages: middle one is digit-free and hits the fallback, the
    # others have normal versions and are not canary-checked.
    fallback = [{ id: "CVE-2017-1111" }]
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return(status: 200, body: {
        results: [
          { vulns: [{ id: "CVE-2024-AAAA" }] },
          { vulns: fallback }, { vulns: fallback },
          { vulns: [{ id: "CVE-2024-CCCC" }] }
        ]
      }.to_json)

    packages = [
      { repo_url: "https://github.com/a/a", version: "v1", name: "a" },
      { repo_url: "https://github.com/b/b", version: "HEAD", name: "b" },
      { repo_url: "https://github.com/c/c", version: "v3", name: "c" }
    ]
    results = @client.query_batch(packages)

    assert_equal 1, results[0].size
    assert_equal "CVE-2024-AAAA", results[0][0]["id"]
    assert_equal [], results[1]
    assert_equal 1, results[2].size
    assert_equal "CVE-2024-CCCC", results[2][0]["id"]
  end

  # The canary must contain no decimal digit. OSV's normalize_tag regex
  # (\d+|(?<![a-z])(rc|alpha|beta|preview)\d*) extracts nothing from a
  # digit-free string, yielding "". That "" then equals the normalized form
  # of any digit-free tag in a CVE's affected list (e.g. "last-cvs-commit",
  # "latest"). A single 0-9 anywhere produces a non-empty normalization and
  # the degenerate match is avoided. ("deadbeef" matches; "deadbeef0" does not.)
  def test_canary_version_has_no_decimal_digits
    refute_match(/[0-9]/, Brew::Vulns::OsvClient::CANARY_VERSION)
  end

  def test_query_batch_slices_at_500_packages
    slice_size = Brew::Vulns::OsvClient::BATCH_SIZE / 2
    total = slice_size + 3

    packages = Array.new(total) do |i|
      { repo_url: "https://github.com/x/p#{i}", version: "v#{i}", name: "p#{i}" }
    end

    captured = []
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return do |req|
        body = JSON.parse(req.body)
        captured << body["queries"]
        # Tag each real-slot result with its position in this request so we
        # can verify global index assignment after the batches are merged.
        results = body["queries"].each_with_index.map do |q, i|
          if q["version"] == Brew::Vulns::OsvClient::CANARY_VERSION
            {}
          else
            { vulns: [{ id: "REQ#{captured.size - 1}-Q#{i}" }] }
          end
        end
        { status: 200, body: { results: results }.to_json }
      end

    results = @client.query_batch(packages)

    # All versions contain digits, so no canaries are sent.
    assert_equal 2, captured.size
    assert_equal slice_size, captured[0].size
    assert_equal 3, captured[1].size

    assert_equal total, results.size

    # First package of batch 0 sits at request 0, query slot 0.
    assert_equal "REQ0-Q0", results[0][0]["id"]
    # Last package of batch 0 sits at request 0, query slot 499.
    assert_equal "REQ0-Q#{slice_size - 1}", results[slice_size - 1][0]["id"]
    # First package of batch 1 sits at request 1, query slot 0.
    assert_equal "REQ1-Q0", results[slice_size][0]["id"]
    # Last package overall sits at request 1, query slot 2.
    assert_equal "REQ1-Q2", results[total - 1][0]["id"]

    # No off-by-one gaps anywhere in the merged results.
    refute results.any?(&:empty?)
  end

  def test_query_batch_canary_detection_works_in_second_slice
    slice_size = Brew::Vulns::OsvClient::BATCH_SIZE / 2

    packages = Array.new(slice_size + 1) do |i|
      { repo_url: "https://github.com/x/p#{i}", version: "v#{i}", name: "p#{i}" }
    end
    packages[slice_size][:version] = "HEAD"

    fallback = [{ id: "CVE-OLD" }]
    call = 0
    stub_request(:post, "https://api.osv.dev/v1/querybatch")
      .to_return do |req|
        call += 1
        n = JSON.parse(req.body)["queries"].size
        if call == 1
          { status: 200, body: { results: Array.new(n) { {} } }.to_json }
        else
          # Second request has one digit-free package: real and canary both
          # get the fallback set.
          { status: 200, body: { results: [{ vulns: fallback }, { vulns: fallback }] }.to_json }
        end
      end

    err = capture_stderr { @results = @client.query_batch(packages) }

    assert_equal slice_size + 1, @results.size
    assert_equal [], @results[slice_size]
    assert_match(/p#{slice_size}/, err)
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

  def test_pagination_aborts_after_max_pages
    # Server keeps echoing a page token forever — without an upper bound the
    # client would loop until it OOMs. Verify it raises a clear ApiError instead.
    stub_request(:post, "https://api.osv.dev/v1/query")
      .to_return(
        { status: 200, body: { vulns: [{ id: "CVE-LOOP" }], next_page_token: "infinite" }.to_json }
      )

    error = assert_raises(Brew::Vulns::OsvClient::ApiError) do
      @client.query(repo_url: "https://github.com/test/repo", version: "v1.0.0")
    end

    assert_match(/more than \d+ pages/, error.message)
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
