# Installed saved-check cadence

This profile runs one finite saved-check tick per systemd wake. Nightshift owns
the exact recurrence slot, stable evaluation identity, retained source/result
record and attention receipt. NQ owns the saved-check evaluation and optional
credential-free local-file delivery. The timer owns only wake cadence.

This is not the retired watchbill path, the historical Observatory fixture
scheduler, a catch-up queue, or authority to perform downstream work. One timer
serves one exact policy/configuration tuple. A missed window produces no check;
the next wake considers only its current slot.

## Profile

Create canonical JSON plus one newline using schema
`nightshift.saved-check-installed-profile/v1`. It has these fields:

```json
{"attention_policy":"/etc/nightshift/saved-check-attention.jcs.json","attention_policy_sha256":"sha256:...","command_timeout_seconds":60,"nightshift_program":"/usr/local/bin/nightshift","nightshift_program_sha256":"sha256:...","nightshift_store":"/var/lib/nightshift/nightshift.sqlite","notification_config":"/etc/nightshift/nq-local-notification.toml","notification_config_sha256":"sha256:...","notification_destination_identity":"local-inbox:operator-attention","notification_route":"operator-attention","nq_program":"/usr/local/bin/nq","nq_program_sha256":"sha256:...","runtime_config":"/etc/nightshift/saved-check-runtime.jcs.json","runtime_config_sha256":"sha256:...","schedule_policy":"/etc/nightshift/saved-check-schedule.jcs.json","schedule_policy_sha256":"sha256:...","scheduler_clock_id":"operator-clock","schema":"nightshift.saved-check-installed-profile/v1","state_directory":"/var/lib/nightshift/saved-check"}
```

Every pinned input is absolute and final-non-symlink. Every input file is pinned
by its exact SHA-256; the store and state locations are separate absolute
runtime paths. After validation, the supervisor copies each enrolled executable
and configuration into a sealed in-memory file and passes that descriptor to
the component. A later content mutation or pathname replacement therefore
cannot change the bytes parsed or executed by that tick. This installed profile
requires Linux `memfd` sealing and `/proc/self/fd` support.

The notification configuration must contain exactly one route:
the selected `local_file` route, with an existing final-non-symlink inbox below
`state_directory`. This reference profile does not support Slack, Discord,
webhooks or secret-bearing routes.

The installed profile accepts a whole-minute-aligned epoch and a 60–86,400
second interval divisible by 60. The timer wakes at each minute boundary;
Nightshift's policy decides whether that minute is due and never catches up a
missed slot. Its admissible delay remains shorter than the interval. Maintenance
is declared through NQ's existing
maintenance interface; its `covered`, `overrun`, `uncovered` or unavailable
state remains explicit in the condition and attention receipt. Maintenance does
not turn a failed check into success.

## Run the disposable public example

[`examples/saved-check-installed-local.py`](../../examples/saved-check-installed-local.py)
exercises the composition without installing a service or changing system
configuration. It creates a 20-row SQLite queue under one fresh local root,
acquires it through Monitor, evaluates the saved check and maintenance
declaration through NQ, runs the Nightshift tick, delivers one local-file
attention record, and inspects both owner stores. It then verifies exact
same-slot replay, overlap refusal, and a missed slot with no catch-up.

Use the exact public component revisions pinned by the matching integration
release manifest. On Linux with Python 3.11+, Rust and Cargo, build those public
clones with:

```sh
cargo build --release --manifest-path constellation-nightshift/runtime/Cargo.toml -p nightshiftd
# The single-user disposable example uses NQ's explicit debug-only
# same-identity helper exception. Installed release builds require a distinct
# enrolled helper account.
cargo build --manifest-path constellation-nq/Cargo.toml -p nq-app
cargo build --release --manifest-path constellation-monitor/Cargo.toml -p monitor-project-concerns
```

Then choose an absolute path that does not exist and run the example from the
Nightshift checkout:

```sh
demo_root=/tmp/saved-check-demo-public-001
test ! -e "$demo_root"
python3 examples/saved-check-installed-local.py \
  --root "$demo_root" \
  --nightshift "$PWD/runtime/target/release/nightshift" \
  --nq /absolute/path/to/constellation-nq/target/debug/nq \
  --monitor /absolute/path/to/constellation-monitor/target/release/monitor-concerns
```

The final JSON names the exact Nightshift evaluation, NQ notification and
retained inspection paths. `commands.jsonl` records command identities and
output digests, not component output. The SQLite databases and local inbox are
the owner records. Keep the root while an outcome is uncertain; remove it only
after inspection when the disposable records are no longer needed.

This example uses real local component processes and real SQLite reads. The
queue and maintenance declaration are intentionally synthetic. Its debug NQ
build uses the explicit debug-only same-UID helper exception so an unprivileged
newcomer can exercise replay without creating a second operating-system
account. That exception is a local substitution fixture, not a supported
installed identity boundary. Local-file delivery establishes custody rather
than human acknowledgment, and no downstream action is authorized. Same-slot
replay proves that the completed composition does not deliver twice. This
example does not inject response loss after NQ has accepted delivery; after
such a loss, inspect the exact NQ notification and Nightshift evaluation before
considering another invocation. It also does not exercise systemd activation
or the system installation boundary described below.

## Install and start

Build and install the exact pinned Nightshift, Monitor and NQ cohort first.
The supervisor requires Python 3.11 or newer for the standard-library TOML
reader. Create the site-owned configs and local inbox outside protected home
directories, then:

```sh
sudo install -d -m 0750 -o root -g nightshift /etc/nightshift
sudo install -d -m 0700 -o nightshift -g nightshift /var/lib/nightshift/saved-check
sudo install -d -m 0711 -o nightshift -g nightshift /var/lib/nightshift/saved-check/inbox
sudo install -d -m 0755 -o root -g root /usr/local/libexec
sudo install -m 0755 deploy/systemd/nightshift-saved-check-tick \
  /usr/local/libexec/nightshift-saved-check-tick
sudo install -m 0640 -o root -g nightshift deploy/systemd/saved-check.env.example \
  /etc/nightshift/saved-check.env
sudo install -m 0644 deploy/systemd/nightshift-saved-check.service \
  deploy/systemd/nightshift-saved-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nightshift-saved-check.timer
```

The shipped service and timer have been parsed from an exact staged system root.
The tick and exact same-slot replay have also been exercised as disposable
`Type=oneshot` user services with the compatible sandbox properties. That run
did not exercise the system `nightshift` user/group, `/etc` environment loading,
the installed `/usr/local` path, the calendar timer wake, or properties that the
unprivileged user manager could not establish (`PrivateDevices`, kernel/control-
group protection, namespace restriction and `RestrictSUIDSGID`). The user
manager also reported that its filesystem namespace setup was unavailable, so
the system service's `ProtectSystem`, `ProtectHome`, `PrivateTmp` and
`ReadWritePaths` isolation remains an operator deployment check. Treat these as
reference system units until that system-level activation is verified in the
target environment; the saved-check composition itself and restart-safe replay
are qualified.

No credential file is required for local delivery. Protect the NQ config and
inbox as operator records even though they contain no remote-delivery secret.
The service refuses symlinked state ancestry, state/tick directories owned by a
different uid, or state/inbox directories writable by group or other. Keep the
state root and tick directories at `0700`; the local inbox may be `0711` so its
path is searchable, but it must remain non-writable by group and other.

## Inspect, stop and restart

```sh
systemctl status nightshift-saved-check.timer nightshift-saved-check.service
journalctl -u nightshift-saved-check.service -n 50
nightshift --store /var/lib/nightshift/nightshift.sqlite saved-check inspect \
  --evaluation-id sha256:EXACT_EVALUATION
systemctl stop nightshift-saved-check.timer
systemctl start nightshift-saved-check.timer
```

The supervisor uses a nonblocking local lock. An overlapping manual invocation
returns exit 75 and launches no component. Repeated wakeup in the same slot
resolves the same evaluation/tick identity; a completed tick is returned from
the retained summary without another source read or delivery. After response
loss, inspect the exact Nightshift evaluation and NQ notification custody before
considering intervention. An `acquisition_started` or `nq_started` result is
indeterminate, not permission to repeat the source operation.

The tick identity is SHA-256 over the profile identity and Nightshift's exact
evaluation identity. Summaries and the exact local delivery intent are retained
under `state_directory/ticks/TICK_HEX/`; the Nightshift and NQ databases remain
the canonical detailed records. The summary never substitutes for inspecting
those owner stores after an uncertain result.

Stopping the timer does not settle an in-flight component attempt. A service
restart safely re-enters the same slot only while that slot remains selected;
otherwise retained state must be inspected explicitly. `Persistent=false`
prevents a boot-time catch-up burst.

## Uninstall and retained records

```sh
sudo systemctl disable --now nightshift-saved-check.timer
sudo rm /etc/systemd/system/nightshift-saved-check.service \
  /etc/systemd/system/nightshift-saved-check.timer
sudo systemctl daemon-reload
```

Do not remove `/var/lib/nightshift`, the NQ database, local inbox, profile or
pinned executables while an outcome is uncertain or records are needed for
inspection. Removal of those records is an explicit operator retention choice,
not part of uninstall. No automatic migration or rollback procedure is claimed.
