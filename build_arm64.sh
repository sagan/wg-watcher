#!/bin/sh

cross +nightly build --target aarch64-unknown-linux-musl \
  -Z build-std=std,core,alloc,panic_unwind \
  --release

