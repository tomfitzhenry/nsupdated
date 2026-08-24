# TODO

## Tests

- Extend the NixOS VM test (`vm-tests/axfrddns.nix`) to exercise deletes,
  RRset replacements, and prerequisites through the real stack, not just an
  add. The in-process `integration_test.go` covers these, but not over
  nsupdate(1) and a live authoritative server.
