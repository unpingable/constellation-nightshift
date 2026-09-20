# Night Shift — systemd deployment

The supported `constellation-nq` saved-check installation is documented in
[`SAVED_CHECK.md`](SAVED_CHECK.md). It composes the current saved-check runtime,
attention receipts and credential-free NQ local inbox without using this
classic watchbill surface.

The `nightshift-watchbill.*` and `watchbill.env.example` files in this
directory are retained historical material. They depend on the retired classic
`nq-monitor`/watchbill composition and are **not an installable or supported
path**. In particular, do not reconstruct their former sibling `wlp` layout or
use their commands as migration instructions.

Only [`SAVED_CHECK.md`](SAVED_CHECK.md) describes the active systemd reference
installation. Historical files remain solely to explain older deployments and
must not be enabled for new ones.
