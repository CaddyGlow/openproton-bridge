# bridge-ui (Tauri + Svelte + Bun)

Desktop UI scaffold for `openproton-bridge`.

## Stack
- Tauri v2 shell (`src-tauri`)
- Svelte + TypeScript frontend (`src`)
- Bun package/runtime tooling

## Prerequisites
- `bun` 1.0+
- Rust toolchain (`rustup`, `cargo`)
- Tauri system deps for your OS

## Install
```bash
bun install
```

## Frontend only
```bash
bun run dev
```

## Desktop app (Tauri)
```bash
bun run tauri:dev
```

## Build
```bash
bun run tauri:build
```

## Current scaffold scope
- Tauri window + tray (show/hide/quit)
- Rust-side app state + command surface
- gRPC adapter with:
  - `grpcServerConfig.json` resolution/loading
  - TLS + `server-token` metadata interceptor
  - `CheckTokens` handshake
  - `RunEventStream` consume loop
- Svelte status dashboard wired to Tauri commands/events

Current limitation: unix `fileSocketPath` transport is not implemented yet in this adapter (TCP+TLS path is implemented).
