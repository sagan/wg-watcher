#!/bin/sh

cross +nightly build --target mipsel-unknown-linux-musl \
  -Z build-std=std,core,alloc,panic_unwind \
  --release

