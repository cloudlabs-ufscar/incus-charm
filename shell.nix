{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  packages = with pkgs; [
    charmcraft
    juju
    python312Packages.tox
  ];
}
