let
  pkgs = import <nixpkgs> {};
  stdenv = pkgs.stdenv;

in stdenv.mkDerivation rec {
  name = "devcgprog";

  buildInputs = with pkgs; [
    go
    gnumake
  ];
}
