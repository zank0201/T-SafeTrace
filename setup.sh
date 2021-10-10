#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# install Rust and select a proper version
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2019-07-08
source $HOME/.cargo/env
rustup component add rust-src && rustup target install aarch64-unknown-linux-gnu arm-unknown-linux-gnueabihf

# install Xargo
rustup default 1.44.0 && cargo +1.44.0 install xargo
# switch to nightly
rustup default nightly-2019-07-08

# initialize Teaclave TrustZone SDK submodule
git submodule update --init -- rust
cd rust/compiler-builtins && git submodule update --init libm
cd ../rust && git submodule update --init src/stdsimd
