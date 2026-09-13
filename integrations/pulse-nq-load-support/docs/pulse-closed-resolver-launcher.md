# Pulse closed resolver launcher

`tools/seal-pulse-support-resolver-launcher.py` creates a single
zero-argument executable named `pulse-support-resolver` for Nightshift's
present-evidence port. It binds one exact Pulse resolver image and one exact
load-support configuration. It is not a producer, receiver, NQ client, or
general command runner.

The enrollment is exact canonical JSON schema
`pulse.nq_host_load_pressure.closed_resolver_launcher_enrollment.v1` with only
these fields:

- `schema`
- `resolver_program` and `resolver_sha256`
- `config_path` and `config_sha256`
- `python_interpreter` and `python_sha256`

All configured paths are absolute regular files. Enrollment is bounded to
64 KiB; the configuration is bounded to 64 KiB; the resolver image is bounded
to 512 MiB. The generator checks the configured content hashes, then creates
the launcher and its manifest with exclusive creation. The manifest schema is
`pulse.nq_host_load_pressure.closed_resolver_launcher_manifest.v1` and records
the descriptor bytes hash as well as both bindings. The output launcher and
manifest must themselves be pinned by the consuming process configuration.

At invocation the launcher rejects every argument, opens each configured
pathname with `O_NOFOLLOW`, captures it into a new Linux `memfd`, checks its
digest, seals the captured image against write, shrink, growth, and seal
replacement, and closes the pathname-backed descriptors. It then executes the
captured resolver image using argv[0] exactly `pulse-support-resolver`, with an
otherwise empty environment containing only:

- `PULSE_LOAD_SUPPORT_CONFIG=/proc/self/fd/N`
- `PULSE_LOAD_SUPPORT_CONFIG_SHA256=sha256:...`

The resolver therefore receives no selected ambient configuration pathname.
Its source accepts this descriptor form only when the path is exactly
`/proc/self/fd/<decimal-fd>` and the captured bytes hash matches. The ordinary
absolute-path configuration form remains available when the digest variable is
absent, preserving the producer and receiver interface.

This relies on Linux `memfd_create`, file seals, and `/proc/self/fd`. It does
not support non-Linux hosts, a resolver built before the descriptor-read source
change, script resolvers, or a deployment whose Python interpreter is outside
the deployment trust boundary. The generator checks the interpreter hash while
it reads the enrollment and emits the launcher. The generated shebang does not
recheck that hash at invocation: runtime trust in that interpreter and its
standard library remains a deployment trust boundary, just as for Docket's
closed launcher. The launcher cannot recursively pin interpreter shared
libraries.

The frozen b126 resolver binary deliberately remains unchanged. It rejects a
`/proc/self/fd/N` configuration because its old regular-file reader rejects
the procfs symlink. A new Pulse resolver binary built from this source revision
is required before the closed launcher can be used for a real Nightshift run.
No actual configuration or key material is included in this source change.

`tools/test-seal-pulse-support-resolver-launcher.py` is a deterministic
synthetic launcher test. It covers descriptor creation, post-enrollment
configuration replacement refusal, argv refusal, role argv[0], and procfd
reopening. It is not a qualification of an actual Pulse binary; that requires
a separately built resolver from this source revision and the existing real
resolver cases.
