{pkgs ? import <nixpkgs> {}, withHoogle ? false}:

let
  gitignoreSrc = pkgs.fetchFromGitHub {
    owner = "hercules-ci";
    repo = "gitignore.nix";
    rev = "211907489e9f198594c0eb0ca9256a1949c9d412";
    sha256 = "06j7wpvj54khw0z10fjyi31kpafkr6hi1k0di13k1xp8kywvfyx8";
  };
  gitignore = import gitignoreSrc { inherit (pkgs) lib; };
  inherit (pkgs.haskell.lib)
    appendConfigureFlags justStaticExecutables appendConfigureFlag dontCheck markUnbroken doHaddock;

  inherit (gitignore) gitignoreSource;

  hxclip-src = gitignoreSource ./.;

  haskellOverrides = self: super: {

    h-gpgme = markUnbroken (dontCheck super.h-gpgme);
    hxclip =
      (justStaticExecutables
        (self.callCabal2nix "hxclip" hxclip-src { }));
  };

  haskellPackages = pkgs.haskellPackages.override {
    overrides = haskellOverrides;
  };

in {
  hxclip = haskellPackages.hxclip;
  shell = haskellPackages.shellFor {
    inherit withHoogle;
    packages = p: [ p.hxclip ];
    buildInputs =
      with haskellPackages;
      [
        ghcid
        cabal-install
        haskell-language-server
        #hlint
        ormolu
        profiteur
        hp2html
        hp2pretty
      ] ++ [ dhall ] ;
  };
}
