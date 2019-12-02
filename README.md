# Generate Keys

```
yarn build
node ./dist/generateKeys.js
```

# Build Client

- Download rustup from https://rustup.rs/
- `rustup target add aarch64-unknown-linux-gnu`

```
cargo build --release --target aarch64-unknown-linux-gnu
```

# Run Server

```
yarn dev
```
