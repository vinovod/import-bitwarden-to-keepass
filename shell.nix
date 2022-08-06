{ pkgs ? import <nixpkgs> {
  # overlays = [
  #   (self: super: {
  #     python = super.python.override {
  #       packageOverrides = python-self: python-super: {
  #         pykeepass = python-super.twisted.overrideAttrs (oldAttrs: {
  #           src = super.fetchPypi {
  #             pname = "pykeepass";
  #             version = "19.10.0";
  #             sha256 =
  #               "7394ba7f272ae722a74f3d969dcf599bc4ef093bc392038748a490f1724a515d";
  #             extension = "tar.bz2";
  #           };
  #         });
  #       };
  #     };
  #   })
  # ];
} }:

with builtins;
let
  inherit (pkgs) stdenv;

  python = "python39";

  mach = import (builtins.fetchGit {
    url = "https://github.com/DavHau/mach-nix";
    ref = "refs/tags/3.5.0";
  }) { inherit pkgs python; };

  pykeepass = mach.buildPythonPackage {
    src =
      "https://github.com/libkeepass/pykeepass/archive/refs/heads/master.zip";
    version = "4.0.3";
    pname = "pykeepass";
    requirements = ''
      lxml
      pycryptodomex
      construct==2.10.68
      argon2-cffi
      python-dateutil
      future
    '';
  };

  # myPythonPackages = pkgs.pythonPackages.override {
  #   overrides = self: super: {
  #     pykeepass = {

  #     };
  #   };
  # };

  # customPython = mach-nix.mkPythonShell {
  #   src = "https://github.com/psf/requests/tarball/2a7832b5b06d";
  #   requirements = "\n";
  # };

  # customPython = myPythonPackages.buildEnv.override {
  #   extraLibs = [ pkgs.python39Packages.pykeepass ];
  # };

  pp = mach.mkPython { # replace with mkPythonShell if shell is wanted
    # requirements = builtins.readFile ./requirements.txt;
    packagesExtra = [ pykeepass ];
  };

in pkgs.mkShell {
  buildInputs = [ pp ];
  shellHook = ''
    set -e

    export $(grep -v '^#' .env | xargs)
    export BW_PATH="${pkgs.bitwarden-cli}/bin/bw"

    if [[ -f $DB_PATH ]]
    then
      rm -rf $DB_PATH
    fi

    if [[ -f $TOTP_DB_PATH ]]
    then
      rm -rf $TOTP_DB_PATH
    fi

    export BW_SESSION=`$BW_PATH login --raw || $BW_PATH unlock --raw`

    if [[ -n $BW_SESSION ]]
    then
      echo "Syncing..."
      $BW_PATH sync
      python import-bitwarden-to-keepass.py
      $BW_PATH lock
    fi

    exit
  '';
}
