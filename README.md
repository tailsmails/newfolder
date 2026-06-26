# newfolder

newfolder is a lightweight, high-performance command-line steganography, file
obfuscation, and secure metadata-destruction workstation written in V. It 
packs files into a sequence of zero-byte, metadata-carrying directory structures,
and features an integrated compliance-grade metadata shredder designed to 
completely purge filesystem-level traces.

---

## Features

### 1. Zero-Byte Steganographic Storage Engine

  - **Zstandard Pre-Compression (Level 19):** Before chunking, the target file is compressed in-place using ZStandard at the highest standard compression level (19). This minimizes storage overhead, significantly reduces the final chunk count, and optimizes the metadata footprint.
  - **Metadata-Only Data Persistence:** Packs compressed segments entirely into filenames inside a target folder. The generated files contain 0 bytes of content, utilizing filesystem directory structures rather than raw block allocations.
      - *Filesystem Footprint:* Offloads file storage from physical disk data blocks into directory entry tables (such as Ext4 directory index blocks, NTFS Index Records, or APFS directory trees), achieving zero-block data allocation per chunk.
  - **Sequential Ordering Preservation:** Automatically embeds masked index keys into filename prefixes, enabling parallel scanning and deterministic reconstruction of the compressed byte stream.

### 2. Cryptographic Core, AEAD, & Decoy Injection

  - **Domain-Separated Argon2 Key Derivation:** Implements memory-hard RFC 9106 Argon2-based key derivation to derive two distinct 256-bit symmetric keys using independent cryptographic salts:
    - **Data Key ($K_{\text{data}}$):** Derived from the user's secret passphrase to encrypt chunk data.
    - **Metadata Key ($K_{\text{meta}}$):** Derived from the separate user-provided seed string to generate the 64-bit Feistel indexing seed.
  - **Custom 64-bit Feistel Cipher:** Obfuscates chunk sequence indices through a custom 4-round Feistel-like network, preventing sequential pattern analysis on directory listings.
      - *Round Function Execution:* Implements a non-linear mixing function:
        $$f(r, k) = ((r \oplus k) \times \text{0x27d4eb2d}) \oplus (r \gg 15)$$
        with round keys scheduled from the Argon2-derived 64-bit metadata seed.
  - **ChaCha20-Poly1305 AEAD Engine:** Encrypts 50-byte compressed chunks in-place using ChaCha20-Poly1305 authenticated encryption. Each block receives:
    - **Confidentiality:** Via ChaCha20 stream encryption.
    - **Integrity & Authenticity:** Via a 16-byte Poly1305 MAC tag appended to the ciphertext.
    - **Deterministic Nonce Derivation:** The 12-byte initialization vector (nonce) is derived deterministically from the block index, guaranteeing that every block uses a unique nonce under the same key without storing the nonce in the filename.
  - **Indistinguishable Decoy (Fake) Block Injection:** Generates a randomized number of decoy files (between 1x and 2x the genuine chunk count) alongside the real files.
    - *Stealth Alignment:* Decoy filenames match the exact layout of genuine files (16 hex characters for the index + 132 hex characters representing a 50-byte chunk and 16-byte MAC tag).
    - *Silent Filtering:* During unpacking, fake files are isolated. Decrypting a fake filename's index yields a random out-of-bounds index value ($index \ge \text{directory file count}$). If a decoy index lands in-bounds by statistical anomaly, its Poly1305 MAC verification fails. In both cases, decoys are silently ignored during reconstruction.

### 3. Progressive File-Metadata Shredder Engine (GNU-Shred Compliance)

  - **Multi-Pass Directory-Entry Saturation (DES):** Overwrites directory-resident filenames in-place with randomized alphanumeric sequences of identical length, neutralizing original filename signatures on disk.
      - *In-Place Scrambling:* Replaces filename record allocations $N$ times with high-entropy alphanumeric noise, ensuring previous names cannot be retrieved via filesystem journal carving or undelete forensics.
  - **Zero-Fill Obfuscation (`-z`):** Appends an optional final pass that overwrites all filename entries with homogeneous '0' character strings.
      - *Pattern Obfuscation:* Masks high-entropy random name patterns with uniform sequences, leaving directory index tables populated with innocent-looking zeroed metadata slots.
  - **Logarithmic Name Contraction & Unlinking (`-u`):** Progressively halves the character length of renamed filenames before executing the final file unlink (`rm`) system call.
      - *Slack Space Elimination:* Successively shrinks filenames to force the filesystem to actively clear and overwrite trailing index record slack spaces:
        $$\text{Length}(N_{k+1}) = \lfloor \text{Length}(N_k) / 2 \rfloor$$

---

## Quick Start (One-Liner)

```bash
pkg update -y && pkg install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/newfolder && cd newfolder && v -prod newfolder.v -o newfolder && ln -sf $(pwd)/newfolder $PREFIX/bin/newfolder
```

---

## Usage

### 1. Packing a File
Compresses and packs a file into a target directory containing empty, zero-byte metadata files mixed with decoy files.
```bash
newfolder pack <input_file_or_-> <output_dir> <passphrase> <seed> [argon2 options]
```

### 2. Unpacking a File
Reconstructs, authenticates, and decompresses the original binary file from the empty metadata files inside the target directory.
```bash
newfolder unpack <input_dir> <output_file_or_-> <passphrase> <seed> [argon2 options]
```

**Argon2 Options (for pack/unpack):**
- `-t <time>`: Sets the Argon2 time cost / iterations (default: 3).
- `-m <memory>`: Sets the Argon2 memory cost in KiB (default: 65536, which is 64MB).
- `-p <threads>`: Sets the Argon2 parallelism / degree of threads (default: 4).
- `-salt <salt>`: Custom salt string for Argon2 key derivation (default: "default_salt_value_123").

### 3. Secure Metadata Shredding
Shreds filenames recursively using multi-pass random overwrites, zero-fills, and unlinking.
```bash
newfolder shred <target_dir> [options]
```

**Shred Options:**
- `-n <passes>`: Sets the number of random overwrite iterations (default: 3).
- `-z`: Appends a final pass overwriting filenames with '0' blocks.
- `-u`: Activates progressive name-shrinking and unlinks the files (and parent directory) after shredding.
- `-v`: Verbose mode (displays step-by-step progress).

---

## Technical Examples

### Packing and Unpacking Sequence (Default Mode)
```bash
# 1. Obfuscate file into zero-byte filename structures with decoy files using default Argon2 parameters
newfolder pack backup.zip ./vault "secure_pass_99" "my_metadata_seed_phrase"

# 2. Reassemble and verify directory metadata back into the original archive
newfolder unpack ./vault restored_backup.zip "secure_pass_99" "my_metadata_seed_phrase"
```

### Packing and Unpacking Sequence (Custom Argon2 Strength)
To customize memory allocation (e.g., 128MB), passes, parallelism, and salt:
```bash
# 1. Pack with 4 iterations, 128MB RAM, 2 threads, and custom salt
newfolder pack backup.zip ./vault "secure_pass_99" "my_metadata_seed_phrase" -t 4 -m 131072 -p 2 -salt "mysupersecretsalt"

# 2. Unpack (you must provide identical parameters to derive the matching keys)
newfolder unpack ./vault restored_backup.zip "secure_pass_99" "my_metadata_seed_phrase" -t 4 -m 131072 -p 2 -salt "mysupersecretsalt"
```

### Advanced Directory Shredding Configuration
```bash
# Shred directory entries with 5 random passes, a final zero pass, 
# name contraction, and final file deletion with real-time logs:
newfolder shred ./vault -n 5 -z -u -v
```

---

## Cryptography & Metadata Destruction Model

1.  **Dual-Key Derivation Pipeline:**
    
    $$\text{Passphrase} + (\text{Salt} + \text{"\_data"}) \xrightarrow{\text{Argon2}} K_{\text{data}} \quad (256\text{-bit Data Key})$$
    
    $$\text{Seed String} + (\text{Salt} + \text{"\_metadata"}) \xrightarrow{\text{Argon2}} K_{\text{meta}} \quad (256\text{-bit Metadata Key}) \rightarrow \text{64-bit Feistel Seed}$$

2.  **Block Transition Map:**
    
    $$\text{Physical File} \xrightarrow{\text{Zstd L19}} \text{Compressed Payload} \rightarrow \text{Chunking } [50\text{B}] \rightarrow \begin{cases} \text{Feistel Index Cipher } (K_{\text{meta}}) \\ \text{ChaCha20-Poly1305 } (K_{\text{data}}) \end{cases} \rightarrow \text{OS Directory Entry}$$

3.  **Entropy Alignment (Real vs. Decoys):**
    
    $$\text{Directory Output} = \{\text{Real Blocks}\} \cup \{\text{Decoy Blocks (Random Hex Layout)}\}$$

4.  **Metadata Overwrite Formula:**
    Each directory-resident filename $N$ of original length $L$ is overwritten with random bytes from the alphanumeric charset $\Sigma$ for $J$ iterations:
    
    $$N_{j} \in \Sigma^L \quad \text{for } j \in [1, \text{passes}]$$

5.  **Destruction Cycle:**
    If the `-u` parameter is enabled, the filename namespace is shrunk and unlinked:
    
    $$\text{Random Scramble} \rightarrow \text{Zero-Fill } [0^L] \rightarrow \text{Logarithmic Contraction} \rightarrow \text{System Unlink } (\text{rm})$$

---

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
