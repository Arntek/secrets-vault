# Homebrew formula for secrets-vault. The version and sha256 lines are
# rewritten for each release by scripts/render-formula.sh; do not edit them by
# hand. See docs/releasing.md.
class SecretsVault < Formula
  desc "Command-line secrets manager with per-vault keys and Touch ID unlock"
  homepage "https://github.com/Arntek/secrets-vault"
  version "0.0.0" # render-formula:version
  license "MIT"

  # BASE is the release download folder; render-formula.sh can point it at a
  # local folder (file://) for testing.
  base = "https://github.com/Arntek/secrets-vault/releases/download/v#{version}" # render-formula:base

  on_macos do
    on_arm do
      url "#{base}/secrets-vault_#{version}_darwin_arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # render-formula:darwin_arm64
    end
    on_intel do
      url "#{base}/secrets-vault_#{version}_darwin_amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # render-formula:darwin_amd64
    end
  end

  on_linux do
    on_arm do
      url "#{base}/secrets-vault_#{version}_linux_arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # render-formula:linux_arm64
    end
    on_intel do
      url "#{base}/secrets-vault_#{version}_linux_amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # render-formula:linux_amd64
    end
  end

  def install
    bin.install "secrets-vault"

    # Short names are links made by the formula itself, so Homebrew tracks
    # them: they are removed on uninstall and follow upgrades. (`post_install`
    # + `secrets-vault alias add` was rejected: it runs in Homebrew's sandbox,
    # writes the user's config from inside an install, and creates links
    # Homebrew doesn't know about, which dangle after an upgrade or uninstall.)
    #
    # "sv" is always linked. "vault" is linked only when no other program
    # called vault is already visible, because HashiCorp Vault uses that name.
    bin.install_symlink "secrets-vault" => "sv"
    bin.install_symlink "secrets-vault" => "vault" unless other_vault
  end

  # Another program called `vault`: one on the user's own PATH (Homebrew's
  # build PATH is filtered, so read the original) or already in Homebrew's bin.
  # A `vault` that resolves to a secrets-vault binary is ours (an earlier
  # version, on upgrade) and doesn't count.
  def other_vault
    dirs = ENV.fetch("HOMEBREW_PATH", ENV.fetch("PATH", "")).split(File::PATH_SEPARATOR)
    dirs << (HOMEBREW_PREFIX/"bin").to_s
    dirs.reject(&:empty?).uniq.each do |d|
      path = File.join(d, "vault")
      next if File.directory?(path) || !File.executable?(path)
      return path if File.basename(File.realpath(path)) != "secrets-vault"
    end
    nil
  end

  def caveats
    <<~EOS
      Commands: secrets-vault (always), sv, and vault.
      The `vault` short name is only added when no other `vault` program is
      installed, because HashiCorp Vault uses that name. If it was skipped
      you will see `sv` only; to take the name anyway, run:
        sv alias add vault --force
      To give `vault` back to another program later: sv alias rm vault
      Scripts that must work everywhere should call `secrets-vault`.

      secrets-vault does not provide shell completions yet.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/secrets-vault version")
    system bin/"sv", "--help"
    assert_predicate bin/"sv", :symlink?
  end
end
