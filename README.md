# newfolder

newfolder is a lightweight, high-performance command-line steganography, file
obfuscation, and secure metadata-destruction workstation written in V. It 
packs standard files into a sequence of zero-byte, metadata-carrying files,
and features an integrated compliance-grade metadata shredder designed to 
completely purge filesystem-level traces.

---

## Features

### 1. Zero-Byte Steganographic Storage Engine

  - **Metadata-Only Data Persistence:** Packs file segments entirely into filenames 
    inside a target folder. The generated files are completely empty (0 bytes in size), 
    utilizing only filesystem directory index structures for storage.
      - *Filesystem Footprint:* Offloads file storage from physical disk data blocks 
        into directory entry tables (such as Ext4 directory index blocks, NTFS 
        Index Records, or APFS directory trees), achieving true zero-block allocation 
        per chunk.
  - **Sequential Ordering Preservation:** Automatically embeds masked index keys 
    into filename prefixes, enabling high-speed parallel scanning and deterministic 
    reconstruction of the original byte stream.

### 2. Cryptographic Core & Block Obfuscation

  - **Custom 64-bit Feistel Cipher:** Obfuscates chunk sequence indices through a 
    custom 4-round Feistel-like network, preventing pattern detection or sequence analysis 
    on directory file lists.
      - *Round Function Execution:* Implements a non-linear mixing function:
        $$f(r, k) = ((r \oplus k) \times \text{0x27d4eb2d}) \oplus (r \gg 15)$$
        with deterministic keys scheduled from a hashed 64-bit user seed.
  - **Dynamic PRNG Stream Cipher:** Encrypts 50-byte chunk payloads in-place using a 
    dynamic shift-multiply pseudo-random generator functioning as a stream cipher.
      - *Initial Vector Isolation:* Re-seeds the PRNG per chunk using:
        $$S_{\text{chunk}} = \text{Seed} \oplus \text{Index}$$
        to guarantee that identical plaintext blocks yield completely divergent, high-entropy 
        hexadecimal ciphertexts.

### 3. Progressive File-Metadata Shredder Engine (GNU-Shred Compliance)

  - **Multi-Pass Directory-Entry Saturation (DES):** Overwrites directory-resident filenames 
    in-place with randomized alphanumeric sequences of identical length, neutralizing 
    original filename signatures on disk.
      - *In-Place Scrambling:* Replaces filename record allocations $N$ times with 
        high-entropy alphanumeric noise, ensuring previous names cannot be retrieved 
        via filesystem journal carving or undelete forensics.
  - **Zero-Fill Obfuscation (`-z`):** Appends an optional final pass that overwrites 
    all filename entries with homogeneous '0' character strings.
      - *Pattern Obfuscation:* Masks high-entropy random name patterns with uniform 
        sequences, leaving directory index tables populated with innocent-looking 
        zeroed metadata slots.
  - **Logarithmic Name Contraction & Unlinking (`-u`):** Progressively halves the 
    character length of renamed filenames before executing the final file unlink (`rm`) system call.
      - *Slack Space Elimination:* Successively shrinks filenames to force the filesystem 
        to actively clear and overwrite trailing index record slack spaces:
        $$\text{Length}(N_{k+1}) = \lfloor \text{Length}(N_k) / 2 \rfloor$$

---

## Quick Start (One-Liner)

```bash
pkg update -y && pkg install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/newfolder && cd newfolder && v -prod newfolder.v -o newfolder && ln -sf $(pwd)/newfolder $PREFIX/bin/newfolder
```

---

## Usage

### 1. Packing a File
Packs a physical file into a directory structure containing empty, zero-byte metadata files.
```bash
newfolder pack <input_file> <output_dir> <seed>
```

### 2. Unpacking a File
Reconstructs the original binary file from the empty metadata files inside the target directory.
```bash
newfolder unpack <input_dir> <output_file> <seed>
```

### 3. Secure Metadata Shredding
Shreds filenames recursively using multi-pass random overwrites, zero-fills, and unlinking.
```bash
newfolder shred <target_dir> [options]
```

**Options:**
- `-n <passes>`: Sets the number of random overwrite iterations (default: 3).
- `-z`: Appends a final pass overwriting filenames with '0' blocks.
- `-u`: Activates progressive name-shrinking and unlinks the files (and parent directory) after shredding.
- `-v`: Verbose mode (displays step-by-step progress).

---

## Technical Examples

### Packing and Unpacking Sequence
```bash
# 1. Obfuscate file into zero-byte filename structures
newfolder pack backup.zip ./vault "secure_pass_99"

# 2. Reassemble directory metadata back into the original archive
newfolder unpack ./vault restored_backup.zip "secure_pass_99"
```

### Advanced Directory Shredding Configuration
```bash
# Shred directory entries with 5 random passes, a final zero pass, 
# name contraction, and final file deletion with real-time logs:
newfolder shred ./vault -n 5 -z -u -v
```

---

## Cryptography & Metadata Destruction Model

1.  **Block Transition Map:**
    
    $$\text{Physical File} \rightarrow \text{Chunking } [50\text{B}] \rightarrow \text{Feistel Index Cipher} \rightarrow \text{Stream Payload Cipher} \rightarrow \text{OS Directory Entry Allocation}$$

2.  **Metadata Overwrite Formula:**
    Each directory-resident filename $N$ of original length $L$ is overwritten with random bytes from the alphanumeric charset $\Sigma$ for $J$ iterations:
    
    $$N_{j} \in \Sigma^L \quad \text{for } j \in [1, \text{passes}]$$

3.  **Destruction Cycle:**
    If the `-u` parameter is enabled, the filename namespace is shrunk and unlinked:
    
    $$\text{Random Scramble} \rightarrow \text{Zero-Fill } [0^L] \rightarrow \text{Logarithmic Contraction} \rightarrow \text{System Unlink } (\text{rm})$$

---

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
