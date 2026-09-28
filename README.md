# xmip-core-transport-ftp

FTP transport: one file is one Stream, its name beside it; a Location lists and retrieves, or stores, in passive binary mode, or accepts clients directly. RFC 959. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location stores on a control connection logged in once per server and kept (`transport::Pool`); the data connection is each transfer's own, which is how stream mode ends a file. The login is the transport capability's `Login`, `anonymous()` unless a user is named. Until 2026-09-27 every store logged in and quit.

A Receive Location lists, retrieves and deletes on the same kept control connection. Until 2026-09-28 every receive logged in and quit.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
