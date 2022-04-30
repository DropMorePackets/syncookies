{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
      pkgs = nixpkgs.legacyPackages.${system};
      llvmPackages = pkgs.llvmPackages_latest;
      in
      {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            llvmPackages.llvm
            llvmPackages.bintools
            rustup
            llvmPackages.lld
            libelf
            pkg-config
            libxml2
            openssl
          ];

          shellHook = ''
            export PATH=$PATH:~/.cargo/bin
            export PATH=$PATH:~/.rustup/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
          '';

          RUSTC_VERSION = pkgs.lib.readFile ./rust-toolchain;
          LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ llvmPackages.libclang.lib ];
          BINDGEN_EXTRA_CLANG_ARGS =
            # Includes with normal include path
            (builtins.map (a: ''-I"${a}/include"'') [
              pkgs.glibc.dev
              pkgs.libxml2
            ])
            # Includes with special directory paths
            ++ [
              ''-I"${llvmPackages.libclang.lib}/lib/clang/${llvmPackages.libclang.version}/include"''
              ''-I"${pkgs.glib.dev}/include/glib-2.0"''
              ''-I${pkgs.glib.out}/lib/glib-2.0/include/''
            ];
        };
      });
}
