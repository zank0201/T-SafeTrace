
# export RUST_TRUST_PATH="/home/zanele/STM32MPU_workspace/incubator-teaclave-trustzone-sdk"
# cd $RUST_TRUST_PATH
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2021-07-29
source $HOME/.cargo/env
rustup component add rust-src && rustup target install aarch64-unknown-linux-gnu arm-unknown-linux-gnueabihf
rustup default 1.54.0 && cargo +1.54.0 install xargo
rustup default nightly-2021-07-29

#git submodule update --init -- rust
#cd rust/compiler-builtins && git submodule update --init libm
#cd ../rust && git submodule update --init src/stdsimd
