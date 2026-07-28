# Why `workspace-root.Cargo.toml` is here

`hanzo-crypto` is a **member of a Cargo workspace whose root is the org-parent
directory** `~/work/hanzo/Cargo.toml` — a file that lives in no git repo at all
and existed only on one machine. All 25 of this crate's dependencies are
`{ workspace = true }`, so the crate cannot resolve, build, or publish without
that root.

`workspace-root.Cargo.toml` is a verbatim copy of it, captured so the crate is
recoverable. It is NOT used by a build from this repo — to build, that file has
to sit one level above the crate directory.

## Known defect in that root, fixed in this copy

It listed `cli` in `workspace.members`, but `hanzo/cli` declares its own
`[workspace]`. Cargo therefore refused every member:

    error: multiple workspace roots found in the same workspace:
      /Users/z/work/hanzo/cli
      /Users/z/work/hanzo

Dropping `cli` from `members` fixes it — verified: `crypto`, `cloud-backend`
and `guard` all resolve afterwards (workspace_root `/Users/z/work/hanzo`,
4 packages), and `cli` still builds standalone as its own workspace.

## To make this crate genuinely standalone

Inline the 25 versions from the root's `[workspace.dependencies]` into
`[dependencies]` here. Not done as part of a backup — that is a real change to
the crate, not a preservation step.
