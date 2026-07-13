# frozen_string_literal: true

module Brew
  module Vulns
    VERSION = "0.5.0"

    DEPRECATION_MESSAGE = <<~MSG.freeze
      brew-vulns is deprecated: `brew vulns` is now built into Homebrew.
      Run `brew update` and use `brew vulns` directly, then remove this
      package with `brew uninstall brew-vulns` or `gem uninstall brew-vulns`.
      See https://github.com/Homebrew/brew/pull/23080 for details.
    MSG
  end
end
