{
  description = "Cpppo development shells for CPython 2.7 and 3.x";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { nixpkgs, ... }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"
      ];
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.permittedInsecurePackages = [ "python-2.7.18.12" "python-2.7.18.12-env" ];
          };

          # The Makefile installs Python dependencies in the selected virtualenv.
          pythonShell = python: command: extraPackages: pkgs.mkShell {
            packages = [ python ] ++ (with pkgs; [ bash cacert git gnumake openssh socat ]) ++ extraPackages;
            CPPPO_NIX_SHELL = "1";
            CPPPO_PYTHON = command;
            shellHook = ''
              unset PYTHONPATH VIRTUAL_ENV
              printf 'cpppo: %s (%s)\n' "$( ${command} --version 2>&1 )" "$(command -v ${command})"
            '';
          };
          py3Shell = python: pythonShell python "python3" [];
          py2 = pkgs.python27.withPackages (ps: [ ps.pip ps.setuptools ]);
        in {
          default = py3Shell pkgs.python313;
          py314 = py3Shell pkgs.python314;
          py313 = py3Shell pkgs.python313;
          py312 = py3Shell pkgs.python312;
          py311 = py3Shell pkgs.python311;
          py27 = pythonShell py2 "python2" [];
          interop = pythonShell pkgs.python313 "python3" (with pkgs; [ stdenv.cc cmake pkg-config ]);
        });
    };
}
