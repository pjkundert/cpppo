{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
in
{
  cpppo_py313 = stdenv.mkDerivation rec {
    name = "python313-with-pytest";

    buildInputs = [
      git
      openssh
      python313
      python313Packages.pytest
    ];
  };

  cpppo_py312 = stdenv.mkDerivation rec {
    name = "python312-with-pytest";

    buildInputs = [
      git
      openssh
      python312
      python312Packages.pytest
    ];
  };
 
  cpppo_py311 = stdenv.mkDerivation rec {
    name = "python311-with-pytest";

    buildInputs = [
      git
      openssh
      python311
      python311Packages.pytest
    ];
  };

  cpppo_py310 = stdenv.mkDerivation rec {
    name = "python310-with-pytest";

    buildInputs = [
      git
      openssh
      python310
      python310Packages.pytest
    ];
  };

  cpppo_py2 = stdenv.mkDerivation rec {
    name = "python2-with-pytest";

    buildInputs = [
      git
      openssh
      python27
      python27Packages.pytest
      python27Packages.pip
    ];
  };
}
