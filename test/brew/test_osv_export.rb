# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestOsvExport < Minitest::Test
  NOW = Time.utc(2026, 6, 28, 12, 0, 0)

  def nvi_formula
    Brew::Vulns::Formula.new(
      "name"     => "nvi",
      "versions" => { "stable" => "1.81.6" },
      "revision" => 6,
      "patches"  => [
        { "strip" => "p0", "file" => "Patches/nvi/patch-common__db.h" },
        {
          "strip"    => "p1",
          "url"      => "https://deb.debian.org/debian/pool/main/n/nvi/nvi_1.81.6-17.debian.tar.xz",
          "type"     => "backport",
          "apply"    => ["patches/31regex_heap_overflow.patch"],
          "resolves" => [{ "type" => "security", "id" => "CVE-2015-2305" }],
        },
      ],
    )
  end

  def test_record_for_builds_minimal_record_without_upstream
    record = Brew::Vulns::OsvExport.record_for(nvi_formula, "CVE-2015-2305", now: NOW)

    assert_equal "1.7.3", record[:schema_version]
    assert_equal "HOMEBREW-nvi-CVE-2015-2305", record[:id]
    assert_equal "2026-06-28T12:00:00Z", record[:modified]
    assert_equal ["CVE-2015-2305"], record[:upstream]
    refute record.key?(:summary)
    refute record.key?(:references)
  end

  def test_record_for_affected_package_and_range
    record = Brew::Vulns::OsvExport.record_for(nvi_formula, "CVE-2015-2305", now: NOW)
    affected = record[:affected].first

    assert_equal "Homebrew", affected[:package][:ecosystem]
    assert_equal "nvi", affected[:package][:name]
    assert_equal "pkg:brew/nvi", affected[:package][:purl]

    events = affected[:ranges].first[:events]

    assert_equal({ introduced: "0" }, events[0])
    assert_equal({ fixed: "1.81.6_6" }, events[1])
  end

  def test_record_for_ecosystem_specific_lists_only_resolving_patches
    record = Brew::Vulns::OsvExport.record_for(nvi_formula, "CVE-2015-2305", now: NOW)
    eco = record[:affected].first[:ecosystem_specific]

    assert_equal "patch", eco[:fix]
    assert_equal 1, eco[:patches].size
    assert_equal "backport", eco[:patches][0][:type]
    assert_equal "https://deb.debian.org/debian/pool/main/n/nvi/nvi_1.81.6-17.debian.tar.xz", eco[:patches][0][:url]
    assert_equal ["patches/31regex_heap_overflow.patch"], eco[:patches][0][:apply]
  end

  def test_record_for_merges_upstream_data
    upstream = {
      "summary"    => "Integer overflow in regcomp",
      "details"    => "Long description.",
      "aliases"    => ["GHSA-aaaa-bbbb-cccc"],
      "severity"   => [{ "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
      "references" => [{ "type" => "ADVISORY", "url" => "https://bugs.debian.org/778412" }],
    }

    record = Brew::Vulns::OsvExport.record_for(nvi_formula, "CVE-2015-2305", upstream: upstream, now: NOW)

    assert_equal "Integer overflow in regcomp", record[:summary]
    assert_equal "Long description.", record[:details]
    assert_equal ["CVE-2015-2305", "GHSA-aaaa-bbbb-cccc"], record[:upstream]
    assert_equal upstream["severity"], record[:severity]
    assert_equal upstream["references"], record[:references]
  end

  def test_full_version_without_revision
    formula = Brew::Vulns::Formula.new("name" => "x", "versions" => { "stable" => "1.0" }, "revision" => 0)

    assert_equal "1.0", formula.full_version

    record = Brew::Vulns::OsvExport.record_for(formula, "CVE-2024-1", now: NOW)

    assert_equal({ fixed: "1.0" }, record[:affected].first[:ranges].first[:events][1])
  end

  def test_run_writes_one_file_per_formula_cve_pair
    libqt = Brew::Vulns::Formula.new(
      "name"     => "libquicktime",
      "versions" => { "stable" => "1.2.4" },
      "revision" => 5,
      "patches"  => [
        {
          "url"      => "https://deb.debian.org/.../libquicktime_1.2.4-12.debian.tar.xz",
          "resolves" => [
            { "type" => "security", "id" => "CVE-2016-2399" },
            { "type" => "security", "id" => "CVE-2017-9122" },
          ],
        },
      ],
    )

    client = Object.new
    def client.get_vulnerability(_id) = nil

    Dir.mktmpdir do |dir|
      written = Brew::Vulns::OsvExport.run([nvi_formula, libqt], dir, client: client, now: NOW)

      assert_equal 3, written.size

      filenames = written.map { |p| File.basename(p) }.sort
      expected = [
        "HOMEBREW-libquicktime-CVE-2016-2399.json",
        "HOMEBREW-libquicktime-CVE-2017-9122.json",
        "HOMEBREW-nvi-CVE-2015-2305.json",
      ]

      assert_equal expected, filenames

      written.each do |p|
        assert File.exist?(p)
        record = JSON.parse(File.read(p))

        assert_equal "Homebrew", record["affected"][0]["package"]["ecosystem"]
      end
    end
  end

  def test_run_survives_upstream_fetch_failure
    client = Object.new
    def client.get_vulnerability(_id) = raise Brew::Vulns::OsvClient::Error, "boom"

    Dir.mktmpdir do |dir|
      written = Brew::Vulns::OsvExport.run([nvi_formula], dir, client: client, now: NOW)

      assert_equal 1, written.size

      record = JSON.parse(File.read(written.first))

      assert_equal ["CVE-2015-2305"], record["upstream"]
      refute record.key?("summary")
    end
  end
end
