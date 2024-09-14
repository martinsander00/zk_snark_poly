# ZK-SNARK Polynomial Circuit

This Rust project implements a zk-SNARK using the Groth16 protocol to prove knowledge of a secret `w` that satisfies the polynomial equation:

x = w^4 + aw^3 + bw^2 + c*w + d


## Requirements

- Rust
- Dependencies:
  ```toml
  [dependencies]
  rand = "0.4"
  bellman_ce = "0.7"
```

## Run the Project
1. Clone the repo
```bash
git clone https://github.com/your_username/zk_snark_poly.git
cd zk_snark_poly
```
2. Build and run
```bash
cargo build
cargo run
```
3. Example output
```csharp
Proof is valid. Alice knows a valid 'w'.
```

