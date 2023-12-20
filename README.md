![CSPRNG Image](CSPRNG.png)
# CSPRNG Library for Noir

## Introduction

The CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) library plays a crucial role in generating random numbers that are unpredictable and essential for maintaining privacy and security in ZKP scenarios.

## Features

- **Multiple Hash Functions:** Supports SHA-256, Blake2s, Keccak256, and soon adding more..
- **Seed Reseeding:** Capability to reseed the RNG, allowing for dynamic changes in the randomness source.
- **Efficient Conversion Methods:** Functions to convert between different data types, ensuring compatibility with ZKP requirements.
- **Robust Testing:** Comprehensive test suite to validate the functionality and reliability of the RNG.
- **Customizable Outputs:** Flexibility in specifying output sizes and formats.

## Code Example

```rust
use dep::std;
use dep::std::hash::{sha256, blake2s, keccak256};

struct CSPRNG {
    seed: [u8; 32],
}

fn main() {
    let initial_seed = [/* ... seed values ... */];
    let mut rng = CSPRNG::new(initial_seed);

    let random_number_sha = rng.generate(0); // Using SHA-256
    let random_number_blake = rng.generate(1); // Using Blake2s
    let random_number_keccak = rng.generate(2); // Using Keccak256

    // Output the generated random numbers
    std::println(f"Random number using SHA-256: {random_number_sha}");
    std::println(f"Random number using Blake2s: {random_number_blake}");
    std::println(f"Random number using Keccak256: {random_number_keccak}");
}
```

## Importance in Zero-Knowledge Proofs

The CSPRNG library is crucial in the context of Zero-Knowledge Proofs due to its ability to generate random, unpredictable numbers, important for ensuring the security and privacy inherent in ZKPs. The unpredictability of these numbers is essential for creating complex cryptographic challenges that can't be easily solved or reverse-engineered, thereby maintaining the integrity of the zero-knowledge proof system.

## Limitations

While the CSPRNG library offers robust functionality, it's important to note the following limitations:

- **Seed Security:** The security of the generated numbers is highly dependent on the seed. If the seed is compromised or poorly chosen, it can affect the randomness and security.
- **Deterministic Output:** Being a pseudo-random generator, if reseeded with the same seed, it will produce the same sequence of outputs.

### Contribution

Contributions are welcome! If you have suggestions for improvements or encounter any issues, please feel free to submit a pull request or raise an issue.

### License

This library is distributed under the Apache License 2.0. See the LICENSE file for more details.
