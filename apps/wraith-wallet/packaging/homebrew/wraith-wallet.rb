# Homebrew Cask for Wraith Wallet (macOS, Apple Silicon).
#
# Self-hosted tap — nothing is submitted to homebrew-cask. Users opt in with:
#   brew tap bitcoin-ghost/ghost https://github.com/bitcoin-ghost/ghost
#   brew install --cask wraith-wallet
#
# The .dmg is ad-hoc signed (so it launches on Apple Silicon) but NOT notarized
# (that needs a paid Apple account, by design). The postflight below strips the
# download quarantine flag from the installed app, so it opens without the
# manual right-click -> Open dance; the real trust anchor is the GPG-signed
# SHA256SUMS on the release, which you should verify out of band.
#
# TEMPLATE: `version` and `sha256` are per-release. A release step must fill the
# real sha256 (from the SHA256SUMS asset) — do NOT commit an invented hash. To
# defer the hash to install time instead, set `sha256 :no_check` (weaker: skips
# Homebrew's checksum verification, so lead users to the GPG SHA256SUMS check).
cask "wraith-wallet" do
  version "1.10.21"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/bitcoin-ghost/ghost/releases/download/wraith-v#{version}/Wraith.Wallet_#{version}_aarch64.dmg",
      verified: "github.com/bitcoin-ghost/ghost/"
  name "Wraith Wallet"
  desc "Desktop wallet for Bitcoin Ghost (light wallet, Wraith CoinJoin, Locks, TAP)"
  homepage "https://github.com/bitcoin-ghost/ghost"

  # Apple Silicon only for v1 — the release ships an aarch64 .dmg only.
  depends_on macos: ">= :big_sur"
  depends_on arch: :arm64

  app "Wraith Wallet.app"

  # The .dmg is ad-hoc signed but not notarized, so a quarantined copy still
  # trips Gatekeeper ("cannot verify the developer") on first launch. Homebrew
  # quarantines cask downloads by default; strip the flag from the installed
  # app so it opens normally. (Verify the GPG-signed SHA256SUMS first — that,
  # not Gatekeeper, is the trust anchor this bypasses.)
  postflight do
    system_command "/usr/bin/xattr",
                   args: ["-dr", "com.apple.quarantine", "#{appdir}/Wraith Wallet.app"]
  end

  # wraithd is the unit of life, not the GUI: closing the window leaves the
  # daemon running. Kill any lingering daemon on uninstall so `brew uninstall`
  # leaves nothing behind.
  uninstall quit:       "org.bitcoinghost.wraith.wallet",
            signal:     ["TERM", "org.bitcoinghost.wraith.wallet"]

  zap trash: [
    "~/Library/Application Support/wraithd",
    "~/Library/Preferences/org.bitcoinghost.wraith.wallet.plist",
    "~/Library/Saved Application State/org.bitcoinghost.wraith.wallet.savedState",
  ]

  caveats <<~EOS
    Wraith Wallet's installer is ad-hoc signed and NOT notarized (no paid Apple
    Developer account, by design). Homebrew removes the quarantine flag for you,
    so the app should open normally.

    Verify the release before trusting it: import the Ghost release key, then
      gpg --verify SHA256SUMS.asc SHA256SUMS
    and confirm this download's hash appears in SHA256SUMS. That GPG-signed
    checksum list — not any vendor certificate — is the trust anchor.
  EOS
end
