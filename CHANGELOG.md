# Changelog

Keep a Changelog format, SemVer. Pre-1.0: breaking changes bump the minor.

## [Unreleased]

## [0.1.0] - 2026-09-21

### Added
- Policies with actors, grants, denials, scope, limits, approval triggers,
  promotion conditions and sunset.
- Compilation to capability grants for the broker and an authorisation for the
  promotion gate, so a policy is enforced by construction.
- Denials beat grants; a policy that both grants and denies an operation is a
  compile error.
- Reporting for wildcard grants, missing promotion conditions and missing
  blast-radius limits.
- Lowering to a hashed Canon constant so policy changes appear in the same
  graph and audit records as code changes.
