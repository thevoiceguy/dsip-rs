# Releasing dsip-rs

dsip-rs uses siphon-rs's release model (siphon-rs `RELEASING.md`), so a consumer of both sees one convention. No
release has been cut yet. The first is stage 5c of `docs/dsip-stack-design.md`, and it makes the repository public.

## The two-layer versioning model

1. **Release tags are CalVer** (`v2026.11.02`). A tag names a snapshot of the whole repository. An aggregate of many
   crates cannot make one honest compatibility promise, so the tag does not try; it is a pinnable, changelog-aligned
   name for a commit.
2. **Crate versions are SemVer** (`dsip-session = 0.2.0`). Compatibility lives at the crate level, in each crate's
   `Cargo.toml`.

Do not copy the date into crate versions, and do not invent a workspace-wide SemVer number.

**A third fact is recorded with each release: the DSIP spec it conforms to.** That is the DSIP tag the `spec/` submodule is
pinned to (`git -C spec describe --tags`, for example `poc-v1.0`), and the release notes say it. Moving the
submodule is at least a minor bump of every crate whose behaviour the move changed.

## Tags

- One annotated tag per release: `vYYYY.MM.DD`, matching the changelog heading. A second release on the same day gets
  `.1`, `.2`, …
- Tags are immutable. A bad release is followed by a new one.
- The tag message lists every crate's version and the DSIP spec tag.

## Crate version bumps

All crates are pre-1.0, so the minor digit is the compatibility boundary:

| Change since the crate's last bump | Bump |
|---|---|
| Breaking API change (signature, return type, removed or renamed item) | minor |
| New public API, additive | minor |
| A submodule move that changes the crate's behaviour | minor |
| Fixes only | patch |
| fmt, clippy chores, test-only edits | none |

A return-type change counts as breaking even when existing callers compile. Inter-crate dependencies are `path`
only, so a bump never edits dependents' manifests.

## Changelog

`CHANGELOG.md` follows Keep a Changelog. Work accumulates under `## [Unreleased]`. A release turns it into
`## [YYYY-MM-DD] — workspace release`, which includes:
1. every crate's version, unchanged ones included;
2. the DSIP spec tag;
3. a **Breaking changes** paragraph naming each break and its PR;
4. the entries.

## Checklist

1. Audit each crate since its last bump and classify it by the table above.
2. Bump the `version` lines.
3. Turn `[Unreleased]` into the dated section.
4. Verify: CI green on the release commit — `cargo test --workspace`, `cargo run -p dsip-cli -- vectors run` with
   zero failures, clippy and docs clean on the pinned toolchain, the demos, the wasm build and the web tests.
5. Open a PR and merge it.
6. Tag the merge commit:
   `git tag -a vYYYY.MM.DD -m "workspace release YYYY-MM-DD (DSIP <spec tag>)

   <crate versions>" <sha>`, then push the tag.
7. `gh release create vYYYY.MM.DD` with the version table, the breaking changes and the pinning snippet.

## Downstream

Consumers use git dependencies pinned to a tag, and pin every `dsip-*` crate to the same tag, once, in
`[workspace.dependencies]`:

```toml
dsip-session = { git = "https://github.com/thevoiceguy/dsip-rs", tag = "v2026.11.02" }
```

Different refs of one repository are different sources to Cargo, which duplicates shared crates and produces
type-mismatch errors.
