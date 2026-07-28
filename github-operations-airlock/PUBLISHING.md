# Publication record

This source is the signed GuardedOps marketplace release. `module.json`
identifies `guardedops/github-operations` v1.1.2, includes the public publisher
key, and is paired with the public signature in `module.sig`.

The repository intentionally does not contain the publisher seed, GitHub
credentials, RailCall vault data, private configuration, or customer data.

Before publishing a later version:

1. Update the version and release documentation together.
2. Run `python tools/sign_module.py . --publisher-record
   ~/.railcall/marketplace_publisher.json` from a trusted local environment.
   The helper validates that the private seed derives the embedded public key,
   signs RailCall's canonical bundle bytes, and verifies the result without
   printing the seed.
3. Run the complete unit, live read-only, signature/tamper, and stock-station
   loader suites.
4. Install the signed bundle on a clean stock station and verify at least one
   real public read plus its receipt.
5. Publish only after the source, signature, README, install command, and
   marketplace version all agree.
