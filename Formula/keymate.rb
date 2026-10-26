# Homebrew formula for keymate. This repository doubles as its own tap:
#
#   brew tap blturan/keymate https://github.com/blturan/keymate
#   brew trust --formula blturan/keymate/keymate
#   brew install keymate
#
# version and sha256 are kept current by the release workflow
# (.github/workflows/release.yml).
class Keymate < Formula
  desc "Set up and manage your hardware security keys"
  homepage "https://github.com/blturan/keymate"
  url "https://github.com/blturan/keymate/releases/download/v0.1.1/keymate-aarch64-apple-darwin"
  version "0.1.1"
  sha256 "58f13d66df3a4f2a54a48bee4068b79b4c08b8643a93262703314341595665a7"
  license "Apache-2.0"

  depends_on arch: :arm64
  depends_on "gh"
  depends_on "git"
  depends_on "libfido2"
  depends_on :macos
  depends_on "openssh"

  def install
    libexec.install Dir["keymate-*"].first => "keymate"
    # A bare binary download doesn't preserve its executable permissions.
    (libexec/"keymate").chmod 0755
    # Put the tools keymate needs first on its PATH, so it never picks up
    # macOS's ssh, which can't use security keys.
    paths = %w[openssh libfido2 gh git].map { |name| formula_opt_bin(name) }
    (bin/"keymate").write_env_script libexec/"keymate", PATH: "#{paths.join(":")}:$PATH"
  end

  test do
    assert_predicate libexec/"keymate", :executable?
    assert_match "keymate", shell_output("#{bin}/keymate --version")
    assert_match "All required tools are installed", shell_output("#{bin}/keymate doctor --deps-only")
  end
end
