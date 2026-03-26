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
          config = {
            permittedInsecurePackages = [
              "python-2.7.18.12"
            ];
          };
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

        pycalendarSrc = pkgs.fetchFromGitHub {
          owner = "apple";
          repo = "ccs-pycalendar";
          rev = "a12dd4e1ce8822b022d4abf2cfe6cc93902ff03f";
          sha256 = "1h79ycga2v6ikm4j7839bs987jay7mf39lkamvmvxrfd0q7r51qh";
        };

        caldavtesterSrc = pkgs.fetchFromGitHub {
          owner = "apple";
          repo = "ccs-caldavtester";
          rev = "bed21e5924275552c1561febc8203a9f194cf737";
          sha256 = "1h1pb6x576d5k6rxqhadrlz1p2qnlz30lp98f0g3xvplm3rra5lz";
        };

        caldavtesterPkg = pkgs.writeShellApplication {
          name = "caldavtester";
          runtimeInputs = [ pkgs.python2 ];
          text = ''
            export PYTHONPATH="${caldavtesterSrc}:${pycalendarSrc}/src''${PYTHONPATH:+:''${PYTHONPATH}}"
            exec ${pkgs.python2}/bin/python ${caldavtesterSrc}/testcaldav.py "$@"
          '';
        };

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
          nativeBuildInputs =
            [
              bunPkg
              caldavtesterPkg
              pkgs.cargo
              pkgs.clippy
              pkgs.pkg-config
              pkgs.protobuf
              pkgs.rustc
              pkgs.rustfmt
            ]
            ++ lib.optionals pkgs.stdenv.isLinux [ pkgs.litmus ];

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
            if [ "$(${pkgs.coreutils}/bin/uname -s)" = "Linux" ]; then
              echo " - DAV compliance: litmus, caldavtester"
            else
              echo " - DAV compliance: caldavtester"
            fi
            echo " - Linux UI libs: gtk3/webkitgtk/libsoup/cairo/pango"
          '';
        };
      });
}
