# Generate Keys

```
yarn build
node ./dist/generateKeys.js
```

# Build Client

Download rustup from https://rustup.rs/

## On the Pi

```
cargo build --release
```

## Cross Compile

Put this in ~/.cargo/config

```
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

Run

```
rustup target add armv7-unknown-linux-gnueabihf
export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_DIR="$PWD/openssl/"
cargo build --release --target armv7-unknown-linux-gnueabihf
```

Built executable is at `./target/armv7-unknown-linux-gnueabihf/release/group-project`

# Run Server

```
yarn dev
```
