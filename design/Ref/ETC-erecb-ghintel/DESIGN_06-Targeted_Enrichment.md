# Targeted Enrichment

`ghintel enrich` accepts repeatable `--repository` / `-r` values and an optional `--limit`.

A selected run creates database work items only for the requested canonical repositories. This prevents unselected repositories from being left pending and keeps a selected run resumable. Repository arguments accept supported GitHub URLs or `owner/name`; every requested identity must already be present in the local database.

`--limit` selects the first canonical repositories in stable identity order. It applies only to a new run and cannot be combined with `resume`, which must retain the original work-item set.

These controls are intended for reviewable rollout of local or cloud enrichment. Provider budgets remain enforced independently of selection.
