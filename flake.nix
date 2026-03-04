{
  description = "openproton-bridge development shell (Rust + Tauri + Bun)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {};
        };
        lib = pkgs.lib;
        bunPkg = if pkgs ? bun-bin then pkgs.bun-bin else pkgs.bun;

        webkitgtkPkg =
          if pkgs ? webkitgtk_4_1 then pkgs.webkitgtk_4_1 else pkgs.webkitgtk;

        libsoupPkg =
          if pkgs ? libsoup_3 then pkgs.libsoup_3 else pkgs.libsoup;

        appindicatorPkg =
          if pkgs ? libayatana-appindicator then
            pkgs.libayatana-appindicator
          else if pkgs ? libappindicator then
            pkgs.libappindicator
          else
            null;

        linuxUiLibs =
          [
            pkgs.atk
            pkgs.cairo
            pkgs.gdk-pixbuf
            pkgs.glib
            pkgs.gtk3
            libsoupPkg
            pkgs.pango
            webkitgtkPkg
          ]
          ++ lib.optional (appindicatorPkg != null) appindicatorPkg;
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            bunPkg
            pkgs.cargo
            pkgs.clippy
            pkgs.pkg-config
            pkgs.protobuf
            pkgs.rustc
            pkgs.rustfmt
          ];

          buildInputs =
            [
              pkgs.openssl
            ]
            ++ lib.optionals pkgs.stdenv.isLinux linuxUiLibs;

          LD_LIBRARY_PATH =
            if pkgs.stdenv.isLinux then lib.makeLibraryPath linuxUiLibs else "";

          shellHook = ''
            export BUN_INSTALL="${"$"}PWD/.bun"
            export BUN_TMPDIR="${"$"}{TMPDIR:-/tmp}"

            echo "openproton-bridge dev shell"
            echo " - Rust toolchain: rustc/cargo/clippy/rustfmt"
            echo " - Frontend tooling: bun"
            echo " - Proto tooling: protoc"
            echo " - Linux UI libs: gtk3/webkitgtk/libsoup/cairo/pango"
          '';
        };
      });
}
