# typed: false
# frozen_string_literal: true

class Vaultspectre < Formula
  desc "Vault secret usage auditor - find missing, unused, and stale secrets"
  homepage "https://github.com/ppiankov/vaultspectre"
  version "VERSION"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ppiankov/vaultspectre/releases/download/vVERSION/vaultspectre_VERSION_darwin_arm64.tar.gz"
      sha256 "SHA256_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/ppiankov/vaultspectre/releases/download/vVERSION/vaultspectre_VERSION_darwin_amd64.tar.gz"
      sha256 "SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ppiankov/vaultspectre/releases/download/vVERSION/vaultspectre_VERSION_linux_arm64.tar.gz"
      sha256 "SHA256_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/ppiankov/vaultspectre/releases/download/vVERSION/vaultspectre_VERSION_linux_amd64.tar.gz"
      sha256 "SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install "vaultspectre"
  end

  test do
    system "#{bin}/vaultspectre", "version"
  end
end
