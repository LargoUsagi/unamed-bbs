# Unamed BBS (Suggestions Welcome)

A **Bulletin Board System (BBS)** with a client/server architecture, written in
[Zig].  The server relays bulletins, responses,  chat, and directory data between operators over one or more 
transports. The client is an interactive **TUI**.

Every message on the wire is **Ed25519-signed**. so that transmissions carried over **HAM radio bands** where encryption
is prohibited.  This allows for communicate where you can validate the source of a message on multiple turns of a
conversation in data modes.

## Features

- **Signed wire protocol** - each frame's payload is compressed (Unishox2) and
  Ed25519-signed; users are authenticated via public keys transmitted with messages.
  Servers have a public key that is transmitted to the client to be a known trusted source.
- **Pluggable transports** - Implement the `Transport` vtable to add a new link layer.
  - **AGWPE** - (TCP protocol spoken by ham-radio TNCs such as Direwolf.
  - **TCP** - Direct client/server links without a TNC.
  - **MeshCore** - Soon (TM)
- **Client side Cache** - Client caches bulletins and other user information locally to minimize network time.
- **Interactive TUI client**

## Build, run, test

Requires **Zig 0.16.0+** on PATH. The build graph produces two executables
(`bbs` client, `bbs_server` server) plus a shared `bbs` module.

```sh
zig build                # compile both executables into zig-out/bin/
zig build run -- [args]        # build + run the client TUI
zig build run-server -- [args] # build + run the server
zig build test                 # run all test blocks (the canonical verification)
```


```sh
zig build -Dtarget=x86_64-windows
zig build -Dtarget=aarch64-linux-musl
```

### Client CLI

```sh
zig build run -- \
  --connect agwpe://tnc.example:8000 \
  --callsign YOURCALL \
  --handle "Your Name" \
  [--key path/to/secret_key] \
  [--bbs-key path/to/server_public_key] \
  [--in-memory]
```

### Server CLI

```sh
zig build run-server -- \
  --callsign BBSRV \
  --key path/to/server_secret_key \
  --store path/to/server.sqlite \
  --motd "Welcome to the BBS" \
  --connect agwpe://tnc.example:8000 \  # outbound transport(s)
  --listen tcp://0.0.0.0:9999           # inbound TCP listener(s)
```

Multiple `--connect` and `--listen` flags may be passed to attach more than one
transport to the server's pool.

### Build Releases

Requires **goreleaser** on PATH.

```sh
goreleaser build --clean --snapshot
```

## Dependencies

Managed by `build.zig.zon`:

- **[zigzag](https://github.com/meszmate/zigzag)** - the TUI framework used by
  the client.
- **[zig-sqlite](https://github.com/vrischmann/zig-sqlite)** - SQLite bindings,
  used by both client and server stores.
- **Unishox2** - vendored C library under