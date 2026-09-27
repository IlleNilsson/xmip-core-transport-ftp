# xmip-core-transport-ftp

FTP transport: one file is one Stream, its name beside it; a Location lists and retrieves, or stores, in passive binary mode, or accepts clients directly. RFC 959. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location stores on a control connection logged in once per server and kept (`transport::Pool`); the data connection is each transfer's own, which is how stream mode ends a file. The login is the transport capability's `Login`, `anonymous()` unless a user is named. Until 2026-09-27 every store logged in and quit.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
