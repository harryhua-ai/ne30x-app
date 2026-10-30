# Release known limitations

> Real, current limitations of the NEAPP05 release pipeline. Items here are
> copied verbatim into every generated release note; keep entries short and
> remove them only when they stop being true.

- Packages are unsigned NEAPP05 (`neapp-v5-unsigned`): no private key, no
  signature, no sequence ledger. Installation requires device firmware with
  unsigned-app admission enabled.
- Only `line-crossing` is packaged today. The pipeline records one app per
  package; multi-app releases are not produced yet.
- The workflow creates unpublished draft releases only. Publishing a draft is
  a separate, per-version human action after explicit User Release GO.
- The git tag for a draft release is materialized by GitHub from the draft's
  stored target commit at publish time. After the draft is created, its
  target commit, notes, and assets must not be edited.
- Batch (repository) version, native version, and UI version are separate
  version lines recorded in each release note and package provenance.
