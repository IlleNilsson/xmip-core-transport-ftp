# xmip-core-transport-ftp

FTP transport: one file is one Stream, its name beside it; a Location lists and retrieves, or stores, in passive binary mode, or accepts clients directly. RFC 959. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location stores on a control connection logged in once per server and kept (`transport::Pool`); the data connection is each transfer's own, which is how stream mode ends a file. The login is the transport capability's `Login`, `anonymous()` unless a user is named. Until 2026-09-27 every store logged in and quit.

A Receive Location lists, retrieves and deletes on the same kept control connection. Until 2026-09-28 every receive logged in and quit.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists the directory (`NLST`) and hands each file back unread; its body is its `RETR`, the data connection read as the runtime asks, never whole in memory, and then the server's `226`. `Accepted` sends `DELE` (unless `delete_after_retrieve = false`). `Refused` sends nothing: a refusal is not a consumption — a Stream refused at a transport gate was never written to the Ledger, so the file is the only copy — and the file is left where it lies. The Location asks its stamp, `SIZE` and `MDTM` (RFC 3659), and remembers it (`transport::Refused`); a later listing asks the stamp of a refused name only, and leaves the file out while it is unchanged. One stored again under its name is a new arrival. A server that answers neither `SIZE` nor `MDTM` cannot say a file is unchanged, so there a refused file is listed, and refused, again on every receive — never lost. The memory is the node process's: a node that starts again receives a refused file once more. `Failed` leaves the file, and the next receive lists it again. The control connection stays in the pool, shared with the arrivals until each is acknowledged; a send that finds a transfer running on it opens a connection of its own. Until 2026-10-02 a receive retrieved and deleted every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
