# Changelog

## [1.0.0](https://github.com/source-cooperative/source-coop-cli/compare/v0.3.0...v1.0.0) (2026-10-19)


### ⚠ BREAKING CHANGES

* existing cached logins are no longer found; run `source-coop login` once after upgrading.

### Features

* **api:** -q for query parameters, one typed -f, and -F for a body file ([#56](https://github.com/source-cooperative/source-coop-cli/issues/56)) ([b4a8274](https://github.com/source-cooperative/source-coop-cli/commit/b4a82742983132742230d81af2afd0a8fff8cde2))
* auth commands: login, status, logout and token under auth ([#46](https://github.com/source-cooperative/source-coop-cli/issues/46)) ([f31ae44](https://github.com/source-cooperative/source-coop-cli/commit/f31ae440c0b86080368844018eb7e3049a26c317))
* cache non-production credentials per proxy host so staging and prod coexist ([#22](https://github.com/source-cooperative/source-coop-cli/issues/22)) ([8673032](https://github.com/source-cooperative/source-coop-cli/commit/8673032fcac898c059f59526df4f4145265cb662))
* dates show as RFC 3339 plus a relative time everywhere ([#55](https://github.com/source-cooperative/source-coop-cli/issues/55)) ([8bc6e2d](https://github.com/source-cooperative/source-coop-cli/commit/8bc6e2d546aa4b6e1c62b4528598ff32dae7f8bc))
* manage members and invitations (member, invitation) ([#57](https://github.com/source-cooperative/source-coop-cli/issues/57)) ([fc59ce9](https://github.com/source-cooperative/source-coop-cli/commit/fc59ce99d8f41cfc583584c722c37d7a253a9ed7))
* one login session for STS and the source.coop API ([#23](https://github.com/source-cooperative/source-coop-cli/issues/23)) ([d55e4b7](https://github.com/source-cooperative/source-coop-cli/commit/d55e4b7d0597436876530eddab1abf70090c6808))
* **picker:** show that / filters what's loaded and Enter searches the server ([#61](https://github.com/source-cooperative/source-coop-cli/issues/61)) ([909f771](https://github.com/source-cooperative/source-coop-cli/commit/909f7714438f9a993bd948b694a61aea8cd2079b))
* product commands: list, view, create, edit and delete, with -i ([#47](https://github.com/source-cooperative/source-coop-cli/issues/47)) ([528d627](https://github.com/source-cooperative/source-coop-cli/commit/528d627ecd90ea460d29a25ba9a125f175ff2ebb))
* product edit offers the visibilities its data connection allows ([#54](https://github.com/source-cooperative/source-coop-cli/issues/54)) ([032dd90](https://github.com/source-cooperative/source-coop-cli/commit/032dd90845b6a17bb185670694e5dd4838b90ff0))
* **product:** edit opens a form of current values instead of asking which fields to change ([#62](https://github.com/source-cooperative/source-coop-cli/issues/62)) ([84e4aea](https://github.com/source-cooperative/source-coop-cli/commit/84e4aeab920e833f5d2cec96d4156a243cd0ee07))
* shared foundation for API-backed commands, and the api command ([#45](https://github.com/source-cooperative/source-coop-cli/issues/45)) ([a0db3e6](https://github.com/source-cooperative/source-coop-cli/commit/a0db3e675faf3b20564e0e67477485094c288e80))
* shell completion for commands, flags and ACCOUNT/PRODUCT names ([#63](https://github.com/source-cooperative/source-coop-cli/issues/63)) ([476b1b0](https://github.com/source-cooperative/source-coop-cli/commit/476b1b033eee007796c6bedf9a23840f28441834))


### Bug Fixes

* **complete:** wait for the keychain password dialog instead of exiting mid-dialog ([#65](https://github.com/source-cooperative/source-coop-cli/issues/65)) ([f2e265e](https://github.com/source-cooperative/source-coop-cli/commit/f2e265ea0d1973dbf228ea518fc71e9f91d29125))
* **product:** an editor that won't open no longer ends the edit form ([#64](https://github.com/source-cooperative/source-coop-cli/issues/64)) ([5ee6c37](https://github.com/source-cooperative/source-coop-cli/commit/5ee6c3787b49bdd861e2e5ac80482dc15f7dff51))
* **product:** offer the data connections the API says an account may use ([#53](https://github.com/source-cooperative/source-coop-cli/issues/53)) ([fd8ea66](https://github.com/source-cooperative/source-coop-cli/commit/fd8ea66a7a4e6f21e1130dbb38a94d59f942695b))
* **product:** recognise a product membership by product_id ([#52](https://github.com/source-cooperative/source-coop-cli/issues/52)) ([abb444a](https://github.com/source-cooperative/source-coop-cli/commit/abb444aed95f4bdcd90099d31883b0ee08395720))

## [0.3.0](https://github.com/source-cooperative/source-coop-cli/compare/v0.2.0...v0.3.0) (2026-09-24)


### Features

* add aws-credentials output format for ~/.aws/credentials ([#12](https://github.com/source-cooperative/source-coop-cli/issues/12)) ([ce52df5](https://github.com/source-cooperative/source-coop-cli/commit/ce52df569c6ba33c717b19a67ebf7a9e3aba39fc))
* refresh expired credentials with a cached refresh token ([#18](https://github.com/source-cooperative/source-coop-cli/issues/18)) ([0373810](https://github.com/source-cooperative/source-coop-cli/commit/0373810236e20ed9a62b154794eba3231c39447a))

## [0.2.0](https://github.com/source-cooperative/source-coop-cli/compare/v0.1.3...v0.2.0) (2026-07-03)


### Features

* accept human-friendly --duration units (90s, 5m, 12h, 1d) ([#10](https://github.com/source-cooperative/source-coop-cli/issues/10)) ([43b746e](https://github.com/source-cooperative/source-coop-cli/commit/43b746ec79a22db89e7d221be3693ecb6dc0eef3))

## [0.1.3](https://github.com/source-cooperative/source-coop-cli/compare/v0.1.2...v0.1.3) (2026-06-26)


### Bug Fixes

* don't print credentials to stdout on login unless --no-cache ([792ea5e](https://github.com/source-cooperative/source-coop-cli/commit/792ea5e6d6a633e8d40a8efe0e3d2ee0d46b4e93))
* don't print credentials to stdout on login unless --no-cache ([d713fff](https://github.com/source-cooperative/source-coop-cli/commit/d713fffa4e13ff47ef5fd6632dd93273158d2048))

## [0.1.2](https://github.com/source-cooperative/source-coop-cli/compare/v0.1.1...v0.1.2) (2026-06-26)


### Bug Fixes

* always send STS requests to the proxy's /.sts endpoint ([99d254a](https://github.com/source-cooperative/source-coop-cli/commit/99d254a1fa45d5c7c7568aaa7d8de8f6663ba61f))
* correct prod OAuth client ID ([49aff3a](https://github.com/source-cooperative/source-coop-cli/commit/49aff3aa0bc207026fe45899441031ff6fb09a19))
* correct staging data-proxy host and role-ARN default ([1726a99](https://github.com/source-cooperative/source-coop-cli/commit/1726a99d732980b95d957186bc27effddec5d62a))
* correct staging OAuth client ID ([f2341b6](https://github.com/source-cooperative/source-coop-cli/commit/f2341b6fef71415707e15a8cac1a4eddd414e025))
* correct staging OAuth client ID ([1d4bd68](https://github.com/source-cooperative/source-coop-cli/commit/1d4bd68f0876bc4909863879062f05475314b0d6))

## [0.1.1](https://github.com/source-cooperative/source-coop-cli/compare/v0.1.0...v0.1.1) (2026-03-06)


### Bug Fixes

* rename formula to avoid conflicts ([53982ac](https://github.com/source-cooperative/source-coop-cli/commit/53982ac50ea0a823fbea62e0754d990d287e1f50))

## 0.1.0 (2026-03-05)


### Features

* add version flag ([a99af5e](https://github.com/source-cooperative/source-coop-cli/commit/a99af5ea15c583a02f7519d8c83bd3ebb9055c52))
* initial CLI setup with cargo-dist and release-please ([ee0e52b](https://github.com/source-cooperative/source-coop-cli/commit/ee0e52b68bda830854d955e342526abdfec71933))
* store credentials via OS Keyring ([c05ca6f](https://github.com/source-cooperative/source-coop-cli/commit/c05ca6f42c0a7210aa7591dded2012a8330639ff))
