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
    assert formula.github?
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

  def test_returns_nil_for_unsupported_urls
    data = {
      "name" => "example",
      "versions" => { "stable" => "1.0.0" },
      "urls" => {
        "stable" => { "url" => "https://example.com/source.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_nil formula.repo_url
    refute formula.github?
    refute formula.supported_forge?
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
    assert formula.gitlab?
    assert formula.supported_forge?
    refute formula.github?
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
    assert formula.codeberg?
    assert formula.supported_forge?
    refute formula.github?
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

  def test_to_osv_query_returns_nil_when_no_repo_url
    data = {
      "name" => "example",
      "versions" => { "stable" => "1.0.0" },
      "urls" => {
        "stable" => { "url" => "https://example.com/source.tar.gz" }
      }
    }

    formula = Brew::Vulns::Formula.new(data)

    assert_nil formula.to_osv_query
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
