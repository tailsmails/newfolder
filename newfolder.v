import os
import rand
import encoding.hex
import crypto.argon2
import compress.zstd
import x.crypto.chacha20poly1305

struct PRNG {
mut:
	state u64
}

fn (mut p PRNG) next_byte() u8 {
	p.state += 0x9e3779b97f4a7c15
	mut z := p.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return u8(z ^ (z >> 31))
}

fn derive_key_argon2(passphrase string, salt string, time u32, memory u32, threads u8) ![]u8 {
	mut salt_bytes := salt.bytes()
	if salt_bytes.len < 8 {
		salt_bytes << []u8{len: 8 - salt_bytes.len, init: 0x00}
	}
	
	hash_bytes := argon2.d_key(passphrase.bytes(), salt_bytes, time, memory, threads, 32) or {
		return error('Argon2 key derivation failed: ${err}')
	}
	return hash_bytes
}

fn f(r u32, k u64) u32 {
	return u32(((r ^ u32(k)) * 0x27d4eb2d) ^ (r >> 15))
}

fn encrypt_u64(val u64, seed u64) u64 {
	k0 := seed
	k1 := seed ^ 0x5555555555555555
	k2 := seed ^ 0xaaaaaaaaaaaaaaaa
	k3 := seed ^ 0xf0f0f0f0f0f0f0f0
	mut l := u32(val >> 32)
	mut r := u32(val)
	tmp0 := r
	r = l ^ f(r, k0)
	l = tmp0
	tmp1 := r
	r = l ^ f(r, k1)
	l = tmp1
	tmp2 := r
	r = l ^ f(r, k2)
	l = tmp2
	tmp3 := r
	r = l ^ f(r, k3)
	l = tmp3
	return (u64(l) << 32) | u64(r)
}

fn decrypt_u64(val u64, seed u64) u64 {
	k0 := seed
	k1 := seed ^ 0x5555555555555555
	k2 := seed ^ 0xaaaaaaaaaaaaaaaa
	k3 := seed ^ 0xf0f0f0f0f0f0f0f0
	mut l := u32(val >> 32)
	mut r := u32(val)
	tmp3 := l
	l = r ^ f(l, k3)
	r = tmp3
	tmp2 := l
	l = r ^ f(l, k2)
	r = tmp2
	tmp1 := l
	l = r ^ f(l, k1)
	r = tmp1
	tmp0 := l
	l = r ^ f(l, k0)
	r = tmp0
	return (u64(l) << 32) | u64(r)
}

fn make_nonce(index u64) []u8 {
	mut nonce := []u8{len: 12}
	mut temp := index
	for i := 7; i >= 0; i-- {
		nonce[i] = u8(temp & 0xff)
		temp >>= 8
	}
	return nonce
}

fn encrypt_chunk_chacha(chunk []u8, index u64, key []u8) ![]u8 {
	nonce := make_nonce(index)
	aad := []u8{}
	ciphertext := chacha20poly1305.encrypt(chunk, key, nonce, aad) or {
		return error('Encryption failed')
	}
	return ciphertext
}

fn decrypt_chunk_chacha(enc_chunk []u8, index u64, key []u8) ![]u8 {
	nonce := make_nonce(index)
	aad := []u8{}
	plaintext := chacha20poly1305.decrypt(enc_chunk, key, nonce, aad) or {
		return error('Decryption or integrity check failed')
	}
	return plaintext
}

fn u64_to_hex(val u64) string {
	mut bytes := []u8{len: 8}
	mut temp := val
	for i := 7; i >= 0; i-- {
		bytes[i] = u8(temp & 0xff)
		temp >>= 8
	}
	return bytes.hex()
}

fn hex_to_u64(s string) !u64 {
	if s.len != 16 {
		return error('Invalid hex length')
	}
	bytes := hex.decode(s) or {
		return error('Hex decode failed')
	}
	mut val := u64(0)
	for i in 0 .. 8 {
		val = (val << 8) | u64(bytes[i])
	}
	return val
}

fn read_all_stdin() []u8 {
	mut std_in := os.stdin()
	mut data := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := std_in.read(mut buf) or { 0 }
		if n <= 0 {
			break
		}
		data << buf[0..n]
	}
	return data
}

fn main() {
	args := os.args
	if args.len < 3 {
		print_usage(args[0])
		exit(1)
	}

	action := args[1]

	if action == 'shred' {
		target_dir := args[2]
		
		mut iterations := 3
		mut zero_final := false
		mut remove := false
		mut verbose := false
		mut journal_count := 0 

		for i := 3; i < args.len; i++ {
			match args[i] {
				'-n' {
					if i + 1 < args.len {
						iterations = args[i + 1].int()
						i++
					}
				}
				'-z' {
					zero_final = true
				}
				'-u' {
					remove = true
				}
				'-v' {
					verbose = true
				}
				'-j' {
					if i + 1 < args.len {
						journal_count = args[i + 1].int()
						i++
					}
				}
				else {
					eprintln('Error: Unknown shred option: ${args[i]}')
					exit(1)
				}
			}
		}

		shred(target_dir, iterations, zero_final, remove, verbose, journal_count) or {
			eprintln('Error: ${err}')
			exit(1)
		}
		exit(0)
	}

	if args.len < 6 {
		print_usage(args[0])
		exit(1)
	}

	param1 := args[2]
	param2 := args[3]
	passphrase := args[4]
	seed_str := args[5]

	if passphrase.len == 0 || seed_str.len == 0 {
		eprintln('Error: Empty passphrase or seed')
		exit(1)
	}
	
	mut time_cost := u32(3)
	mut memory_cost := u32(65536)
	mut parallelism := u8(4)
	mut salt_str := 'default_salt_value_123'
	
	for i := 6; i < args.len; i++ {
		match args[i] {
			'-t' {
				if i + 1 < args.len {
					time_cost = u32(args[i + 1].int())
					if time_cost <= 0 {
						time_cost = 3
					}
					i++
				}
			}
			'-m' {
				if i + 1 < args.len {
					memory_cost = u32(args[i + 1].int())
					if memory_cost <= 0 {
						memory_cost = 65536
					}
					i++
				}
			}
			'-p' {
				if i + 1 < args.len {
					parallelism = u8(args[i + 1].int())
					if parallelism <= 0 {
						parallelism = 4
					}
					i++
				}
			}
			'-salt' {
				if i + 1 < args.len {
					salt_str = args[i + 1]
					i++
				}
			}
			else {
				eprintln('Error: Unknown pack/unpack option: ${args[i]}')
				exit(1)
			}
		}
	}
	
	data_key := derive_key_argon2(passphrase, salt_str + '_data', time_cost, memory_cost, parallelism) or {
		eprintln('Error: ${err}')
		exit(1)
	}

	metadata_key := derive_key_argon2(seed_str, salt_str + '_metadata', time_cost, memory_cost, parallelism) or {
		eprintln('Error: ${err}')
		exit(1)
	}

	mut seed := u64(0)
	for i in 0 .. 8 {
		seed = (seed << 8) | u64(metadata_key[i])
	}

	if action == 'pack' {
		pack(param1, param2, data_key, seed) or {
			eprintln('Error: ${err}')
			exit(1)
		}
	} else if action == 'unpack' {
		unpack(param1, param2, data_key, seed) or {
			eprintln('Error: ${err}')
			exit(1)
		}
	} else {
		eprintln('Error: Unknown action')
		exit(1)
	}
}

fn print_usage(program_name string) {
	eprintln('Usage:')
	eprintln('  ${program_name} pack <input_file_or_-> <output_dir> <passphrase> <seed> [argon2 options]')
	eprintln('  ${program_name} unpack <input_dir> <output_file_or_-> <passphrase> <seed> [argon2 options]')
	eprintln('  ${program_name} shred <target_path> [options]')
	eprintln('\nOptions for pack/unpack (Argon2 Key Derivation):')
	eprintln('  -t <time>    Time cost / iterations (default: 3)')
	eprintln('  -m <memory>  Memory cost in KiB (default: 65536)')
	eprintln('  -p <threads> Parallelism / degree of threads (default: 4)')
	eprintln('  -salt <salt> Custom salt string (default: "default_salt_value_123")')
	eprintln('\nOptions for shred:')
	eprintln('  -n <passes>  Number of random overwrite iterations (default: 3)')
	eprintln('  -z           Add a final overwrite pass with zeros')
	eprintln('  -u           Deallocate and remove files after shredding')
	eprintln('  -v           Verbose output (print progress)')
	eprintln('  -j <count>   Journal saturation file count (default: 0 for auto-detect, fallback to 1500)')
}

fn pack(file_path string, output_dir string, data_key []u8, seed u64) ! {
	mut data := []u8{}
	
	if file_path == '-' {
		data = read_all_stdin()
	} else {
		if !os.exists(file_path) {
			return error('File not found')
		}
		if os.is_dir(file_path) {
			return error('Path is a directory')
		}
		data = os.read_bytes(file_path) or {
			return error('Read failed')
		}
	}

	if data.len == 0 {
		return error('Empty input data')
	}
	
	compressed_data := zstd.compress(data, compression_level: 19) or {
		return error('Zstd compression failed: ${err}')
	}

	if os.exists(output_dir) {
		if !os.is_dir(output_dir) {
			return error('Not a directory')
		}
		items := os.ls(output_dir) or {
			return error('Read dir failed')
		}
		if items.len > 0 {
			return error('Directory is not empty')
		}
	} else {
		os.mkdir_all(output_dir) or {
			return error('Mkdir failed')
		}
	}

	chunk_size := 50
	mut index := u64(0)

	for i := 0; i < compressed_data.len; i += chunk_size {
		end := if i + chunk_size < compressed_data.len { i + chunk_size } else { compressed_data.len }
		chunk := compressed_data[i..end].clone()

		enc_index := encrypt_u64(index, seed)
		enc_chunk := encrypt_chunk_chacha(chunk, index, data_key) or {
			return error('Failed to encrypt chunk: ${err}')
		}
		file_name := u64_to_hex(enc_index) + enc_chunk.hex()
		file_path_out := os.join_path(output_dir, file_name)

		if os.exists(file_path_out) {
			return error('File exists')
		}
		os.write_file(file_path_out, '') or {
			return error('File creation failed')
		}
		index++
	}
	
	mut limit := int(index)
	if limit <= 0 {
		limit = 1
	}
	num_fake_files := (rand.intn(limit) or { 0 }) + int(index)
	charset := '0123456789abcdef'
	
	for _ in 0 .. num_fake_files {
		mut fake_enc_index := ''
		for _ in 0 .. 16 {
			idx := rand.intn(charset.len) or { 0 }
			fake_enc_index += charset[idx..idx+1]
		}
		mut fake_enc_chunk := ''
		for _ in 0 .. 132 {
			idx := rand.intn(charset.len) or { 0 }
			fake_enc_chunk += charset[idx..idx+1]
		}
		
		fake_file_name := fake_enc_index + fake_enc_chunk
		fake_file_path := os.join_path(output_dir, fake_file_name)
		
		if os.exists(fake_file_path) {
			continue
		}
		os.write_file(fake_file_path, '') or {
			continue
		}
	}

	println('Success: Packed ${index} real blocks and ${num_fake_files} decoy blocks.')
}

fn unpack(input_dir string, output_file string, data_key []u8, seed u64) ! {
	if !os.exists(input_dir) {
		return error('Directory not found')
	}
	if !os.is_dir(input_dir) {
		return error('Not a directory')
	}

	items := os.ls(input_dir) or {
		return error('Read dir failed')
	}

	mut chunks_map := map[u64][]u8{}

	for item in items {
		if item.len < 50 {
			continue
		}

		enc_index_hex := item[0..16]
		enc_chunk_hex := item[16..]

		enc_index := hex_to_u64(enc_index_hex) or {
			continue
		}

		index := decrypt_u64(enc_index, seed)
		
		if index >= u64(items.len) {
			continue
		}

		enc_chunk := hex.decode(enc_chunk_hex) or {
			continue
		}

		if index in chunks_map {
			continue
		}
		
		chunk := decrypt_chunk_chacha(enc_chunk, index, data_key) or {
			continue
		}
		chunks_map[index] = chunk
	}

	if chunks_map.len == 0 {
		return error('No valid blocks found. Incorrect passphrase/seed or corrupted data.')
	}
	
	mut compressed_bytes := []u8{}
	for i := u64(0); i < u64(chunks_map.len); i++ {
		if i !in chunks_map {
			return error('Missing block sequence at index ${i}. The archive is incomplete.')
		}
		compressed_bytes << chunks_map[i]
	}
	
	decompressed_bytes := zstd.decompress(compressed_bytes) or {
		return error('Zstd decompression failed. The data might be corrupted.')
	}
	
	if output_file == '-' {
		mut out := os.stdout()
		out.write(decompressed_bytes) or {
			return error('Write to stdout failed')
		}
	} else {
		os.write_bytes(output_file, decompressed_bytes) or {
			return error('Write failed')
		}
		println('Success: Unpacked and decompressed successfully')
	}
}

fn generate_random_dir_name() string {
	charset := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	mut rand_name := '.cache_'
	for _ in 0 .. 10 {
		rand_idx := rand.intn(charset.len) or { 0 }
		rand_name += charset[rand_idx..rand_idx+1]
	}
	return rand_name
}

fn saturate_journal(target_path string, verbose bool, user_count int) ! {
	if verbose {
		println('Starting safe journal saturation...')
	}

	mut num_files := u64(0)

	if user_count > 0 {
		num_files = u64(user_count)
		if verbose {
			println('  Using user-specified transaction count: ${num_files}')
		}
	} else {
		mut journal_size_mb := u64(16)
		mut block_size_bytes := u64(4096)
		mut detected := false

		df_res := os.execute('df -P "${target_path}"')
		if df_res.exit_code == 0 {
			lines := df_res.output.split_into_lines()
			if lines.len >= 2 {
				parts := lines[1].fields()
				if parts.len > 0 {
					partition := parts[0]
					
					mut dump_res := os.execute('dumpe2fs -h "${partition}" 2>/dev/null')
					
					if dump_res.exit_code != 0 {
						dump_res = os.execute('tune2fs -l "${partition}" 2>/dev/null')
					}

					if dump_res.exit_code == 0 {
						dump_lines := dump_res.output.split_into_lines()
						for line in dump_lines {
							line_lower := line.to_lower()
							if line_lower.contains('journal size') {
								words := line.split(':')
								if words.len > 1 {
									val_str := words[1].trim_space().replace('M', '').replace('K', '')
									val := val_str.int()
									if val > 0 {
										journal_size_mb = u64(val)
										detected = true
									}
								}
							} else if line_lower.contains('block size') {
								words := line.split(':')
								if words.len > 1 {
									val := words[1].trim_space().int()
									if val > 0 {
										block_size_bytes = u64(val)
										detected = true
									}
								}
							}
						}
					}
				}
			}
		}

		if detected {
			total_journal_blocks := (journal_size_mb * 1024 * 1024) / block_size_bytes
			num_files = total_journal_blocks / 2
			if verbose {
				println('  Auto-detected - Journal Size: ${journal_size_mb}MB, Block Size: ${block_size_bytes} bytes')
			}
		} else {
			num_files = 1500
			if verbose {
				println('  System tools missing or error. Using safe default transaction count: ${num_files}')
			}
		}
	}

	dummy_name := generate_random_dir_name()
	dummy_dir := os.join_path(target_path, dummy_name)

	os.mkdir(dummy_dir) or {
		return error('Failed to create stealthy folder: ${err}')
	}

	if verbose {
		println('  Generating dummy metadata in ${dummy_name}...')
	}
	for i in 0 .. num_files {
		file_path := os.join_path(dummy_dir, 'd_${i}')
		os.write_file(file_path, '') or { break }
	}

	os.execute('sync')

	if verbose {
		println('  Cleaning dummy metadata...')
	}
	os.rmdir_all(dummy_dir) or {
		return error('Failed to remove dummy folder: ${err}')
	}

	os.execute('sync')

	if verbose {
		println('Journal saturation complete.')
	}
}

fn shred(target string, iterations int, zero_final bool, remove bool, verbose bool, journal_count int) ! {
	mut target_files := []string{}
	mut is_dir := false

	if os.is_dir(target) {
		is_dir = true
		items := os.ls(target) or { return err }
		for item in items {
			full_path := os.join_path(target, item)
			if os.is_file(full_path) {
				target_files << full_path
			}
		}
	} else if os.is_file(target) {
		target_files << target
	} else {
		return error('Target does not exist or is not accessible: ${target}')
	}

	if target_files.len == 0 {
		if remove && is_dir {
			os.rmdir(target) or { return err }
			if verbose {
				println('Target directory was already empty and has been removed.')
			}
		}
		return
	}

	if verbose {
		println('Found ${target_files.len} files to shred. (Passes: ${iterations}, Zero-fill: ${zero_final}, Remove: ${remove})')
	}

	charset := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

	for i, mut path in target_files {
		if !os.exists(path) {
			continue
		}
		dir_path := os.dir(path)
		mut current_name := os.file_name(path)
		original_len := current_name.len

		if verbose {
			println('Shredding metadata node ${i + 1}/${target_files.len} (Current Name: ${current_name})...')
		}
		
		for pass := 1; pass <= iterations; pass++ {
			mut rand_name := ''
			for _ in 0 .. original_len {
				rand_idx := rand.intn(charset.len) or { 0 }
				rand_name += charset[rand_idx..rand_idx+1]
			}
			
			new_path := os.join_path(dir_path, rand_name)
			os.rename(path, new_path) or {
				continue
			}
			path = new_path
			current_name = rand_name
		}
		
		if zero_final {
			if verbose {
				println('  Final pass: Writing zero pattern...')
			}
			mut zero_name := ''
			for _ in 0 .. original_len {
				zero_name += '0'
			}
			new_path := os.join_path(dir_path, zero_name)
			os.rename(path, new_path) or {
				unsafe { goto skip_zero }
			}
			path = new_path
			current_name = zero_name
			skip_zero:
		}
		
		if remove {
			if verbose {
				println('  Truncating metadata index sequence...')
			}
			mut temp_name := current_name
			for temp_name.len > 1 {
				temp_name = temp_name[0..temp_name.len / 2]
				new_path := os.join_path(dir_path, temp_name)
				os.rename(path, new_path) or { break }
				path = new_path
			}

			if verbose {
				println('  Unlinking file...')
			}
			os.rm(path) or {
				return error('Failed to remove file: ${path} (${err})')
			}
		}
	}
	
	if remove {
		if is_dir {
			parent_dir := os.dir(os.real_path(target))

			if verbose {
				println('Removing parent container directory: ${target}')
			}
			os.rmdir(target) or {
				return error('Failed to remove root parent directory: ${target} (${err})')
			}

			saturate_journal(parent_dir, verbose, journal_count) or {
				if verbose {
					eprintln('Warning: Journal saturation encountered an issue: ${err}')
				}
			}
		}
	}

	println('Success: Shredding sequence completed.')
}
