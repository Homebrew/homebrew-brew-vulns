# Homebrew/brew-vulns (merged into Homebrew/brew)

This repository provided `brew vulns`, which checks Homebrew formulae for known
vulnerabilities using the [OSV.dev](https://osv.dev) database.

It has been entirely merged into [Homebrew/brew](https://github.com/Homebrew/brew)
as a built-in command. Run `brew update` and continue using `brew vulns` directly.

The tap and gem are no longer maintained. Remove them with:

```shell
brew uninstall brew-vulns
brew untap homebrew/brew-vulns

# If installed through RubyGems:
gem uninstall brew-vulns
```
