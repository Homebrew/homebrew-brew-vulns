# frozen_string_literal: true

require "test_helper"

class TestFormula < Minitest::Test
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

  def test_load_installed_filters_by_name
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
      formulae = Brew::Vulns::Formula.load_installed("vim")
      assert_equal 1, formulae.size
      assert_equal "vim", formulae[0].name
    end
  end

  def test_load_installed_filters_versioned_formulae
    brew_json = {
      "formulae" => [
        {
          "name" => "python@3.11",
          "versions" => { "stable" => "3.11.0" },
          "urls" => { "stable" => { "url" => "https://github.com/python/cpython/archive/refs/tags/v3.11.0.tar.gz" } }
        },
        {
          "name" => "python@3.12",
          "versions" => { "stable" => "3.12.0" },
          "urls" => { "stable" => { "url" => "https://github.com/python/cpython/archive/refs/tags/v3.12.0.tar.gz" } }
        }
      ]
    }.to_json

    success_status = Minitest::Mock.new
    success_status.expect :success?, true

    Open3.stub :capture2, [brew_json, success_status] do
      formulae = Brew::Vulns::Formula.load_installed("python")
      assert_equal 2, formulae.size
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

  def test_load_with_dependencies_includes_deps
    brew_json = {
      "formulae" => [
        {
          "name" => "vim",
          "versions" => { "stable" => "9.1.0" },
          "urls" => { "stable" => { "url" => "https://github.com/vim/vim/archive/refs/tags/v9.1.0.tar.gz" } }
        },
        {
          "name" => "gettext",
          "versions" => { "stable" => "0.22" },
          "urls" => { "stable" => { "url" => "https://github.com/gnu/gettext/archive/refs/tags/v0.22.tar.gz" } }
        },
        {
          "name" => "lua",
          "versions" => { "stable" => "5.4.0" },
          "urls" => { "stable" => { "url" => "https://github.com/lua/lua/archive/refs/tags/v5.4.0.tar.gz" } }
        }
      ]
    }.to_json

    deps_output = "gettext\nlua\n"

    success_status = Minitest::Mock.new
    2.times { success_status.expect :success?, true }

    call_count = 0
    capture_mock = lambda do |*args|
      call_count += 1
      if call_count == 1
        [brew_json, success_status]
      else
        [deps_output, success_status]
      end
    end

    Open3.stub :capture2, capture_mock do
      formulae = Brew::Vulns::Formula.load_with_dependencies("vim")
      names = formulae.map(&:name).sort
      assert_equal ["gettext", "lua", "vim"], names
    end
  end

  def test_load_with_dependencies_without_filter_returns_all
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
      formulae = Brew::Vulns::Formula.load_with_dependencies
      assert_equal 2, formulae.size
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
