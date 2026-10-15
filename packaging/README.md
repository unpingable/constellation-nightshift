# Nightshift packaged executable identity

## Executable build identity

The packaged native tools accept `--build-info`, `--version` and `-V` as sole
arguments before configuration, stdin or state access. These probes report
compile-time source/build declarations, compiler, target and profile. Missing
development declarations remain JSON null and cannot be packaged.

Export `NIGHTSHIFT_SOURCE_COMMIT` as the full lowercase 40-digit source commit and
`NIGHTSHIFT_BUILD_IDENTITY` as a unique build label (1..256 printable ASCII bytes
without spaces) for compilation and assembly. The builder must verify the source
export and locked toolchain inputs; the probe does not independently attest them.
Malformed nonempty declarations fail compilation. Assembly probes the staged
copies, checks their declared identity, compiler/profile/architecture and version,
and embeds their SHA-256 hashes at `/usr/share/doc/` under the package name in
`build-identity.json`. A matching `.build-identity.json` sidecar accompanies the
package. Compare installed probes and hashes to those receipts.

Run `python3 -B -m unittest discover -s packaging -p test_build_identity.py` for
package correspondence and refusal fixtures. No authority, state or core protocol
semantics change. Existing legacy version interfaces remain available.
