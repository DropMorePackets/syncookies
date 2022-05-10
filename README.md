# syncookies

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
2. Install a rust nightly toolchain: `rustup install nightly`
3. Install bpf-linker: `cargo install bpf-linker`
4. If you use the nix-flake install via: `cargo install --git https://github.com/aya-rs/bpf-linker --tag v0.9.3 --no-default-features --features system-llvm -- bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
