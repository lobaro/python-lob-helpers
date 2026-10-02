# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.0.12](https://github.com/lobaro/python-lob-helpers/compare/v0.0.11...v0.0.12) (2026-10-02)


### Features

* **driver_cfg:** add DriverCfg base for tool config sections ([262aeaf](https://github.com/lobaro/python-lob-helpers/commit/262aeafc066af2b6ceded1ca9882c70a5cb90a0f))


### Bug Fixes

* **cli:** reject options add_renamed_argument cannot alias ([3cfdad6](https://github.com/lobaro/python-lob-helpers/commit/3cfdad6c44c57c7c320e6a7a85a86dfa8864892e))
* **driver_cfg:** keep extra keyword only and drop None from it ([279bc56](https://github.com/lobaro/python-lob-helpers/commit/279bc56eb1a79748ea42766473befe121d0ef477)), closes [#20](https://github.com/lobaro/python-lob-helpers/issues/20)
* **hlpr:** parse hex files without an extended address record ([e5c3290](https://github.com/lobaro/python-lob-helpers/commit/e5c32905d4afda1e71449f4672994a449fe98482))
* **hlpr:** pass the end keyword of lob_print to print ([83e2aa7](https://github.com/lobaro/python-lob-helpers/commit/83e2aa7ea1924d4141cd49dc43634199f70932f6))
* parse -dirty/-unknown suffix in firmware identifiers ([903b0ad](https://github.com/lobaro/python-lob-helpers/commit/903b0adc42c906dd12e234bf011cc53c7e137326))

### [0.0.11](https://github.com/lobaro/python-lob-helpers/compare/v0.0.10...v0.0.11) (2026-08-11)


### Features

* **cli:** keep old flag spellings working when an option is renamed ([65a5868](https://github.com/lobaro/python-lob-helpers/commit/65a586806c923dd017bcad9227fc5f6128f79790))


### Bug Fixes

* **cli:** only forward the option settings that were actually set ([5e4fe0e](https://github.com/lobaro/python-lob-helpers/commit/5e4fe0eb5d3a866e667c94f53ac73aca78805b49))

### [0.0.10](https://github.com/lobaro/python-lob-helpers/compare/v0.0.9...v0.0.10) (2026-07-07)


### Features

* **lib_types:** Extend fw version with prerelease ([43b4d76](https://github.com/lobaro/python-lob-helpers/commit/43b4d76d2e0f6fa077107541aaaeff08a6b50354))

### [0.0.9](https://github.com/lobaro/python-lob-helpers/compare/v0.0.8...v0.0.9) (2026-05-20)


### Features

* lob_print splits lines in logs ([dc995fc](https://github.com/lobaro/python-lob-helpers/commit/dc995fc16dddbf2846e6b6cadfdde4de11d45822))


### Bug Fixes

* AI tries to fix ascleandict again ([1265936](https://github.com/lobaro/python-lob-helpers/commit/12659360c6e3d8d80a8d2e631971452fd4560d79))
* enhance lob_print to support custom separators in log messages ([90a7a1a](https://github.com/lobaro/python-lob-helpers/commit/90a7a1aa9a2353e8255a2df2989c229155959422))
* ensure log directory is created only if it exists ([0ebff9b](https://github.com/lobaro/python-lob-helpers/commit/0ebff9b1ad8e7b9dd8bc4efbf419ecb7bcfc874a))
* threadsafe lob_print ([bc6ad90](https://github.com/lobaro/python-lob-helpers/commit/bc6ad90f0111a53538b9d783178630b35b63196c))

### [0.0.8](https://github.com/lobaro/python-lob-helpers/compare/v0.0.7...v0.0.8) (2026-04-08)


### Features

* Enhance ascleandict to handle non-picklable fields ([e25f4de](https://github.com/lobaro/python-lob-helpers/commit/e25f4de2a89599db06831d4120278f64a6e71b25))

### [0.0.7](https://github.com/lobaro/python-lob-helpers/compare/v0.0.6...v0.0.7) (2026-03-04)


### Bug Fixes

* **parse_dmc:** Fail if no MPP start ([a4a4351](https://github.com/lobaro/python-lob-helpers/commit/a4a43514278f2137cac92cb549696afc0a4d969d))
