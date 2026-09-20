# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

Per-version release notes for tagged releases are published on the [GitHub Releases page](https://github.com/WYRE-AI/cisco-duo-mcp/releases) - `semantic-release` generates them from commit history at release time.

## [Unreleased]

### Added

- Initial v1 release: 22 read-only tools covering users (and their enrolled MFA methods - groups, phones, hardware tokens, WebAuthn credentials, U2F tokens), phones, hardware tokens, Duo Desktop tokens, groups, integrations (metadata only, secret fields stripped), the authentication/administrator/telephony logs, and a side-effect-free credential check. Authenticates with Duo's signed-request scheme (Auth Signature v5, HMAC-SHA512) - not OAuth2, not a bearer token; every request is freshly signed with the account's integration key + secret key. Every response passes through a defensive secret-field stripper regardless of endpoint. No bypass-code tool exists (neither the read that returns live codes nor the generator), and no delete/disassociate/settings-write tool exists anywhere - see README's Scope section for the full excluded-endpoint list.
