# xmip-core-transport-ftp

FTP transport: one file is one Stream, its name beside it; a Location lists, claims and retrieves, or stores, in passive binary mode, or serves clients directly. RFC 959; FTPS (RFC 4217) behind the `tls` feature. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location stores on a control connection logged in once per server and kept (`transport::Pool`); the data connection is each transfer's own, which is how stream mode ends a file. The login is the transport capability's `Login`, `anonymous()` unless the address names a user. Until 2026-09-27 every store logged in and quit. A store writes the Message to its data connection as it is read from the Ledger, a piece at a time, never whole in memory (`Sending::Streamed`, 2026-10-19), and a receive claims no more files of a listing than the runtime has room for, the rest left for the next listing.

A Receive Location lists, claims, retrieves and deletes on the same kept control connection. Until 2026-09-28 every receive logged in and quit.

## The claim

A file is taken once it is finished, and by one node (ADR-0024, amendment 2026-10-13): several receiving nodes may poll one directory, and whichever claims a file has it. The claim is the file family's, written once in the transport capability (`transport::claim`), in FTP's words (`src/control.rs`):

- A listing is `MLSD` (RFC 3659), its facts giving each entry's kind, size and modification time; a server that does not answer it is listed by `NLST`, each name stamped by `SIZE` and `MDTM`. A file is taken by the listing after the one that found its stamp unchanged — the stability check — so a file still being stored is left.
- Its turn is `MKD <name>.xmip-claim`, which a server refuses where anything of that name exists, and inside it `MKD <name>.xmip-claim/<node>`, so a starting node finds the turns it left. The claim is `RNFR` and `RNTO` to `<name>.xmip-claim.<node location, percent-encoded>.<nanoseconds>`; the turn is removed with `RMD`.
- A node built by the runtime (`Configured::on_node`) returns every claim its name still holds on the server, and removes its turns, at its first receive that reaches the server, so a server out of reach never stops a node starting, and a Send Location never connects for it.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive hands each claimed file back unread; its body is its `RETR`, the data connection read as the runtime asks, never whole in memory, and then the server's `226`. `Accepted` sends `DELE` of the claimed name: the verdict decides, never a setting (ADR-0024, amendment 2026-10-28). `Refused` renames it back under its dropped name: a refusal is not a consumption — a Stream refused at a transport gate was never written to the Ledger, so the file is the only copy — and remembers its stamp (`transport::Refused`), so a later listing leaves it out while it is unchanged; one stored again under its name is a new arrival. `Failed`, or an arrival let go without a verdict, renames it back, and a later receive lists it again. A return asks `SIZE` of the dropped name first and renames back only where nothing lies there; otherwise the file is held under its claimed name, with why (`FtpTransport::held`), and goes back once the name is free. A server whose `RNTO` replaces an existing file could still lose one a producer drops between the `SIZE` and the `RNTO`, which no FTP command prevents; Xmip's own server refuses such an `RNTO`. The memory of refusals is the node process's: a node that starts again receives a refused file once more. The control connection stays in the pool, shared with the arrivals until each is acknowledged; a send that finds a transfer running on it opens a connection of its own. Until 2026-10-02 a receive retrieved and deleted every file before handing it back; until 2026-10-13 it claimed nothing, and two nodes on one directory could both take a file.

## FTPS

With the `tls` feature, `FtpTransport::secured` — or an address entered as `ftps://`, the server checked against the operating system's trust store for the address's host or `tls_name` — speaks FTPS: `AUTH TLS` turns the control connection over to the estate's TLS (`xmip-core-library-tls`, ADR-0033) before the login, and `PBSZ 0` and `PROT P` guard every data connection, each resuming the control connection's session where the server keeps one. A transfer ends with TLS's own close, and the closing side reads what the peer still sends before it closes, so a socket is never reset with the end of a file unread. Without the feature, an `ftps://` address is refused.

## The far end

`Session` serves one client over a directory held in memory (`Store`), with `MKD`, `RMD`, `RNFR`, `RNTO`, `DELE`, `MLSD`, `SIZE` and `MDTM` as the claim needs, and FTPS where it is given a certificate; `serving` serves every client a listener accepts at once over one shared `Store` (`transport::concurrent`): what several receiving nodes race at, as the Playground's drop box does.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

## The address alone

A Location is entered by its address (ADR-0064, amendment 2026-10-28): `ftp://user@host:21/dir` or `ftps://user@host/dir`; an address without a scheme is a path, the file transport's, though `FtpTransport::open` still takes `host:21` bare where code builds it. The scheme says FTPS, the user part who logs in — anonymous where it names no one, the password the secret the Location names (`secret = "<name>"`, set with `Set-XmipSecret`) — the port is 21 where it names none (`PORT`), and the path the directory a Location lists and stores in (`CWD`). The `user`, `tls` and `delete_after_retrieve` settings are deleted; `timeout` and `tls_name` remain.
