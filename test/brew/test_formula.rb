# frozen_string_literal: true

require "test_helper"

class TestFormula < Minitest::Test
  include SilenceOutput

  def test_extracts_repo_url_from_github_archive_url
    data = {
      "name" => "act",
      "versions" => { "stable" => "0.2.84" },
      "urls" => {
        "stable" => { "url" => "https://github.com/nektos/act/archive/refs/tags/v0.2.84.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://github.com/nektos/act", formula.repo_url
    assert_equal "v0.2.84", formula.tag
  end

  def test_extracts_tag_without_v_prefix
    data = {
      "name" => "abseil",
      "versions" => { "stable" => "20250814.1" },
      "urls" => {
        "stable" => { "url" => "https://github.com/abseil/abseil-cpp/archive/refs/tags/20250814.1.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://github.com/abseil/abseil-cpp", formula.repo_url
    assert_equal "20250814.1", formula.tag
  end

  def test_extracts_repo_url_from_releases_download_url
    data = {
      "name" => "example",
      "versions" => { "stable" => "1.2.3" },
      "urls" => {
        "stable" => { "url" => "https://github.com/owner/repo/releases/download/v1.2.3/source.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://github.com/owner/repo", formula.repo_url
    assert_equal "v1.2.3", formula.tag
  end

  def test_extracts_repo_url_from_head_url_when_stable_not_github
    data = {
      "name" => "aom",
      "versions" => { "stable" => "3.13.1" },
      "urls" => {
        "stable" => { "url" => "https://aomedia.googlesource.com/aom.git" },
        "head" => { "url" => "https://github.com/AomediaOrg/aom.git" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://github.com/AomediaOrg/aom", formula.repo_url
  end

  def test_repo_url_nil_for_non_forge_tarball_without_head
    data = {
      "name" => "libquicktime",
      "versions" => { "stable" => "1.2.4" },
      "urls" => {
        "stable" => { "url" => "https://downloads.sourceforge.net/project/libquicktime/libquicktime/1.2.4/libquicktime-1.2.4.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_nil formula.repo_url
    assert_nil formula.to_osv_query
  end

  def test_extracts_repo_url_from_gitlab_archive_url
    data = {
      "name" => "example",
      "versions" => { "stable" => "1.2.3" },
      "urls" => {
        "stable" => { "url" => "https://gitlab.com/owner/repo/-/archive/v1.2.3/repo-v1.2.3.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://gitlab.com/owner/repo", formula.repo_url
  end

  def test_extracts_repo_url_from_codeberg_archive_url
    data = {
      "name" => "example",
      "versions" => { "stable" => "1.2.3" },
      "urls" => {
        "stable" => { "url" => "https://codeberg.org/owner/repo/archive/v1.2.3.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://codeberg.org/owner/repo", formula.repo_url
  end

  def test_uses_stable_git_url_and_tag_for_non_forge_host
    data = {
      "name" => "aom",
      "versions" => { "stable" => "3.14.1" },
      "urls" => {
        "stable" => { "url" => "https://aomedia.googlesource.com/aom.git", "tag" => "v3.14.1" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://aomedia.googlesource.com/aom.git", formula.repo_url
    assert_equal "v3.14.1", formula.tag
    assert_equal({ repo_url: "https://aomedia.googlesource.com/aom.git", version: "v3.14.1", name: "aom" },
                 formula.to_osv_query)
  end

  def test_prefers_explicit_stable_tag_over_url_parsing
    data = {
      "name" => "argo",
      "versions" => { "stable" => "4.0.6" },
      "urls" => {
        "stable" => { "url" => "https://github.com/argoproj/argo-workflows.git", "tag" => "v4.0.6" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://github.com/argoproj/argo-workflows", formula.repo_url
    assert_equal "v4.0.6", formula.tag
  end

  def test_falls_back_to_head_url_and_version_for_non_forge_tarball
    data = {
      "name" => "coreutils",
      "versions" => { "stable" => "9.11" },
      "urls" => {
        "stable" => { "url" => "https://ftpmirror.gnu.org/gnu/coreutils/coreutils-9.11.tar.xz" },
        "head" => { "url" => "https://git.savannah.gnu.org/git/coreutils.git" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://git.savannah.gnu.org/git/coreutils.git", formula.repo_url
    assert_equal "9.11", formula.tag
    assert_equal({ repo_url: "https://git.savannah.gnu.org/git/coreutils.git", version: "9.11", name: "coreutils" },
                 formula.to_osv_query)
  end

  def test_to_osv_query_returns_hash_with_required_fields
    data = {
      "name" => "vim",
      "versions" => { "stable" => "9.1.2050" },
      "urls" => {
        "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.2050.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)
    query = formula.to_osv_query

    assert_equal "https://github.com/vim/vim", query[:repo_url]
    assert_equal "v9.1.2050", query[:version]
    assert_equal "vim", query[:name]
  end

  def test_to_osv_query_returns_nil_when_head_url_but_no_version
    data = {
      "name" => "example",
      "urls" => {
        "head" => { "url" => "https://git.example.com/repo.git" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal "https://git.example.com/repo.git", formula.repo_url
    assert_nil formula.tag
    assert_nil formula.to_osv_query
  end

  def test_resolved_vulnerability_ids_extracts_security_ids_across_patches
    data = {
      "name"    => "libquicktime",
      "patches" => [
        {
          "strip"    => "p1",
          "url"      => "https://deb.debian.org/debian/pool/main/libq/libquicktime/libquicktime_1.2.4-12.debian.tar.xz",
          "type"     => "backport",
          "resolves" => [
            { "type" => "security", "id" => "CVE-2016-2399" },
            { "type" => "security", "id" => "CVE-2017-9122" },
          ],
        },
        {
          "strip"    => "p1",
          "url"      => "https://example.com/extra.diff",
          "resolves" => [
            { "type" => "security", "id" => "GHSA-xr7r-f8xq-vfvv" },
            { "type" => "security", "id" => "CVE-2017-9122" },
          ],
        },
      ],
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal ["CVE-2016-2399", "CVE-2017-9122", "GHSA-XR7R-F8XQ-VFVV"], formula.resolved_vulnerability_ids
  end

  def test_resolved_vulnerability_ids_skips_security_resolves_without_id
    data = {
      "name"    => "x",
      "patches" => [
        {
          "resolves" => [
            { "type" => "security" },
            { "type" => "security", "id" => nil },
            { "type" => "security", "id" => "" },
            { "type" => "security", "id" => "CVE-2024-1234" },
          ],
        },
      ],
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal ["CVE-2024-1234"], formula.resolved_vulnerability_ids
  end

  def test_resolved_vulnerability_ids_ignores_defect_resolves
    data = {
      "name"    => "innoextract",
      "patches" => [
        {
          "strip"    => "p1",
          "url"      => "https://github.com/dscharrer/innoextract/commit/264c2fe.patch",
          "type"     => "backport",
          "resolves" => [
            { "type" => "defect", "id" => "https://github.com/dscharrer/innoextract/pull/169" },
          ],
        },
      ],
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_empty formula.resolved_vulnerability_ids
  end

  def test_resolved_vulnerability_ids_empty_when_patches_missing
    data = { "name" => "vim", "versions" => { "stable" => "9.1.0" } }

    formula = Brew::Vulns::Formula.new(data)

    assert_empty formula.patches
    assert_empty formula.resolved_vulnerability_ids
  end

  def test_resolved_vulnerability_ids_handles_patches_without_resolves
    data = {
      "name"    => "gecode",
      "patches" => [
        { "strip" => "p1", "url" => "https://github.com/Gecode/gecode/commit/c0ca0e5.patch", "type" => "cherry-pick" },
        { "strip" => "p1", "data" => true },
      ],
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_empty formula.resolved_vulnerability_ids
  end

  def test_resolves_matches_vulnerability_id_case_insensitively
    data = {
      "name"    => "glibc",
      "patches" => [
        { "resolves" => [{ "type" => "security", "id" => "CVE-2024-2961" }] },
      ],
    }
    formula = Brew::Vulns::Formula.new(data)
    vuln = Brew::Vulns::Vulnerability.new("id" => "cve-2024-2961")

    assert formula.resolves?(vuln)
  end

  def test_resolves_matches_via_vulnerability_alias
    data = {
      "name"    => "glibc",
      "patches" => [
        { "resolves" => [{ "type" => "security", "id" => "CVE-2024-2961" }] },
      ],
    }
    formula = Brew::Vulns::Formula.new(data)
    vuln = Brew::Vulns::Vulnerability.new("id" => "GHSA-aaaa-bbbb-cccc", "aliases" => ["CVE-2024-2961"])

    assert formula.resolves?(vuln)
  end

  def test_resolves_returns_false_when_no_match
    data = {
      "name"    => "glibc",
      "patches" => [
        { "resolves" => [{ "type" => "security", "id" => "CVE-2024-2961" }] },
      ],
    }
    formula = Brew::Vulns::Formula.new(data)
    vuln = Brew::Vulns::Vulnerability.new("id" => "CVE-2024-9999")

    refute formula.resolves?(vuln)
  end

  def test_resolves_returns_false_when_no_patches
    formula = Brew::Vulns::Formula.new("name" => "vim")
    vuln = Brew::Vulns::Vulnerability.new("id" => "CVE-2024-1234")

    refute formula.resolves?(vuln)
  end

  def test_cyclonedx_pedigree_maps_patch_data
    formula = Brew::Vulns::Formula.new(
      "name"    => "x",
      "patches" => [
        {
          "url"      => "https://example.com/a.patch",
          "type"     => "cherry_pick",
          "resolves" => [
            { "type" => "security", "id" => "CVE-1" },
            { "type" => "defect", "id" => "BUG-2" },
          ],
        },
        { "type" => "backport" },
        { "url" => "https://example.com/c.patch" },
      ],
    )

    pedigree = formula.cyclonedx_pedigree

    assert_equal 3, pedigree[:patches].size

    p1 = pedigree[:patches][0]

    assert_equal "cherry-pick", p1[:type]
    assert_equal "https://example.com/a.patch", p1[:diff][:url]
    assert_equal [{ type: "security", id: "CVE-1" }, { type: "defect", id: "BUG-2" }], p1[:resolves]

    p2 = pedigree[:patches][1]

    assert_equal "backport", p2[:type]
    refute p2.key?(:diff)
    refute p2.key?(:resolves)

    assert_equal "unofficial", pedigree[:patches][2][:type]
  end

  def test_cyclonedx_pedigree_nil_when_no_patches
    assert_nil Brew::Vulns::Formula.new("name" => "x").cyclonedx_pedigree
    assert_nil Brew::Vulns::Formula.new("name" => "x", "patches" => []).cyclonedx_pedigree
  end

  def test_dependencies_list
    data = {
      "name" => "vim",
      "versions" => { "stable" => "9.1.0" },
      "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/v9.1.0.tar.gz" } },
      "dependencies" => ["gettext", "libsodium", "lua"]
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_equal ["gettext", "libsodium", "lua"], formula.dependencies
  end

  def test_load_all_parses_brew_eval_all_output
    brew_json = {
      "formulae" => [
        {
          "name" => "vim",
          "versions" => { "stable" => "9.1.0" },
          "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
        },
        {
          "name" => "a2ps",
          "versions" => { "stable" => "4.15.8" },
          "urls" => { "stable" => { "url" => "https://ftpmirror.gnu.org/gnu/a2ps/a2ps-4.15.8.tar.gz" } }
        }
      ],
      "casks" => []
    }.to_json

    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    Open3.stub :capture2, [brew_json, success_status] do
      formulae = Brew::Vulns::Formula.load_all

      assert_equal 2, formulae.size
      assert_equal "vim", formulae[0].name
      assert_equal "https://github.com/vim/vim", formulae[0].repo_url
      assert_equal "a2ps", formulae[1].name
      assert_nil formulae[1].repo_url
    end
  end

  def test_load_all_raises_on_brew_failure
    failed_status = Minitest::Mock.new
    failed_status.expect :success?, false
    failed_status.expect :exitstatus, 1

    Open3.stub :capture2, ["", failed_status] do
      assert_raises(Brew::Vulns::Error) do
        Brew::Vulns::Formula.load_all
      end
    end
  end

  def test_load_named_queries_brew_info_without_installed
    brew_json = {
      "formulae" => [
        {
          "name" => "vim",
          "versions" => { "stable" => "9.1.0" },
          "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
        },
        {
          "name" => "curl",
          "versions" => { "stable" => "8.5.0" },
          "urls" => { "stable" => { "url" => "https://github.com/curl/curl/archive/refs/tags/curl-8_5_0.tar.gz" } }
        }
      ]
    }.to_json

    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    capture_mock = lambda do |*args|
      assert_equal ["brew", "info", "--json=v2", "vim", "curl"], args
      [brew_json, success_status]
    end

    Open3.stub :capture2, capture_mock do
      formulae = Brew::Vulns::Formula.load_named(["vim", "curl"])
      assert_equal 2, formulae.size
      assert_equal "vim", formulae[0].name
      assert_equal "curl", formulae[1].name
    end
  end

  def test_load_named_returns_empty_for_empty_input
    assert_equal [], Brew::Vulns::Formula.load_named([])
  end

  def test_load_named_raises_on_brew_failure
    failed_status = Minitest::Mock.new
    failed_status.expect :success?, false
    failed_status.expect :exitstatus, 1

    Open3.stub :capture2, ["", failed_status] do
      assert_raises(Brew::Vulns::Error) do
        Brew::Vulns::Formula.load_named(["nonexistent"])
      end
    end
  end

  def test_load_named_with_deps_includes_dependencies
    brew_json = {
      "formulae" => [
        {
          "name" => "vim",
          "versions" => { "stable" => "9.1.0" },
          "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
        }
      ]
    }.to_json

    deps_json = {
      "formulae" => [
        {
          "name" => "gettext",
          "versions" => { "stable" => "0.22" },
          "urls" => { "stable" => { "url" => "https://github.com/gnu/gettext/archive/refs/tags/v0.22.tar.gz" } }
        }
      ]
    }.to_json

    success_status = Minitest::Mock.new
    3.times { success_status.expect :success?, true }

    capture_mock = lambda do |*args|
      case args
      when ["brew", "info", "--json=v2", "vim"]
        [brew_json, success_status]
      when ["brew", "deps", "vim"]
        ["gettext\n", success_status]
      when ["brew", "info", "--json=v2", "gettext"]
        [deps_json, success_status]
      end
    end

    Open3.stub :capture2, capture_mock do
      formulae = Brew::Vulns::Formula.load_named(["vim"], include_deps: true)
      names = formulae.map(&:name).sort
      assert_equal ["gettext", "vim"], names
    end
  end

  def test_load_installed_parses_brew_output
    brew_json = {
      "formulae" => [
        {
          "name" => "vim",
          "versions" => { "stable" => "9.1.0" },
          "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
        },
        {
          "name" => "curl",
          "versions" => { "stable" => "8.5.0" },
          "urls" => { "stable" => { "url" => "https://github.com/curl/curl/archive/refs/tags/curl-8_5_0.tar.gz" } }
        }
      ]
    }.to_json

    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    Open3.stub :capture2, [brew_json, success_status] do
      formulae = Brew::Vulns::Formula.load_installed
      assert_equal 2, formulae.size
      assert_equal "vim", formulae[0].name
      assert_equal "curl", formulae[1].name
    end
  end

  def test_load_installed_raises_on_brew_failure
    failed_status = Minitest::Mock.new
    failed_status.expect :success?, false
    failed_status.expect :exitstatus, 1

    Open3.stub :capture2, ["", failed_status] do
      assert_raises(Brew::Vulns::Error) do
        Brew::Vulns::Formula.load_installed
      end
    end
  end

  def test_parse_brewfile_uses_brew_bundle_list
    bundle_output = "vim\ncurl\nopenssl\n"

    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    File.stub :exist?, true do
      Open3.stub :capture2, [bundle_output, success_status] do
        names = Brew::Vulns::Formula.parse_brewfile("/path/to/Brewfile")
        assert_equal ["vim", "curl", "openssl"], names
      end
    end
  end

  def test_load_from_brewfile_raises_when_file_not_found
    assert_raises(Brew::Vulns::Error) do
      Brew::Vulns::Formula.load_from_brewfile("/nonexistent/Brewfile")
    end
  end

  def test_load_from_brewfile_returns_empty_when_no_formulae
    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    File.stub :exist?, true do
      Open3.stub :capture2, ["", success_status] do
        formulae = Brew::Vulns::Formula.load_from_brewfile("/path/to/Brewfile")
        assert_equal [], formulae
      end
    end
  end
end
