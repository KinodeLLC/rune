# Changelog

keep a changelog format, semver. before 1.0 a breaking change bumps the minor.

## [Unreleased]

## [0.1.0] - 2026-09-21

### Added
- policies with actors, grants, denials, scope, limits, triggers, conditions
- compiles to capability grants and a promotion authorisation
- denials beat grants, granting and denying the same thing will not compile
- wildcard grants and missing conditions get reported
- lowers to a hashed canon constant
