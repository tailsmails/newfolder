import os
import rand
import encoding.hex
import crypto.argon2

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

fn derive_seed_argon2(passphrase string, salt string, time u32, memory u32, threads u8) !u64 {
	mut salt_bytes := salt.bytes()
	if salt_bytes.len < 8 {
		salt_bytes << []u8{len: 8 - salt_bytes.len, init: 0x00}
	}
	
	hash_bytes := argon2.d_key(passphrase.bytes(), salt_bytes, time, memory, threads, 8) or {
		return error('Argon2 key derivation failed: ${err}')
	}

	mut val := u64(0)
	for i in 0 .. 8 {
		val = (val << 8) | u64(hash_bytes[i])
	}
	return val
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

fn crypt_chunk(chunk []u8, index u64, seed u64) []u8 {
	mut prng := PRNG{state: seed ^ index}
	mut result := []u8{cap: chunk.len}
	for b in chunk {
		result << b ^ prng.next_byte()
	}
	return result
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

		for i := 3; i < args.len; i++ {
			match args[i] {
				'-n' {
					if i + 1 < args.len {
						iterations = args[i + 1].int()
						if iterations <= 0 {
							iterations = 3
						}
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
				else {
					eprintln('Error: Unknown shred option: ${args[i]}')
					exit(1)
				}
			}
		}

		shred(target_dir, iterations, zero_final, remove, verbose) or {
			eprintln('Error: ${err}')
			exit(1)
		}
		exit(0)
	}

	if args.len < 5 {
		print_usage(args[0])
		exit(1)
	}

	param1 := args[2]
	param2 := args[3]
	seed_str := args[4]

	if seed_str.len == 0 {
		eprintln('Error: Empty seed')
		exit(1)
	}
	
	mut time_cost := u32(3)
	mut memory_cost := u32(65536)
	mut parallelism := u8(4)
	mut salt_str := 'default_salt_value_123'
	
	for i := 5; i < args.len; i++ {
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
	
	seed := derive_seed_argon2(seed_str, salt_str, time_cost, memory_cost, parallelism) or {
		eprintln('Error: ${err}')
		exit(1)
	}

	if action == 'pack' {
		pack(param1, param2, seed) or {
			eprintln('Error: ${err}')
			exit(1)
		}
	} else if action == 'unpack' {
		unpack(param1, param2, seed) or {
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
	eprintln('  ${program_name} pack <input_file_or_-> <output_dir> <passphrase> [argon2 options]')
	eprintln('  ${program_name} unpack <input_dir> <output_file_or_-> <passphrase> [argon2 options]')
	eprintln('  ${program_name} shred <target_dir> [options]')
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
}

fn pack(file_path string, output_dir string, seed u64) ! {
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

	for i := 0; i < data.len; i += chunk_size {
		end := if i + chunk_size < data.len { i + chunk_size } else { data.len }
		chunk := data[i..end].clone()

		enc_index := encrypt_u64(index, seed)
		enc_chunk := crypt_chunk(chunk, index, seed)
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

	println('Success: Packed ${index} blocks')
}

fn unpack(input_dir string, output_file string, seed u64) ! {
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
		if item.len < 18 {
			continue
		}

		enc_index_hex := item[0..16]
		enc_chunk_hex := item[16..]

		enc_index := hex_to_u64(enc_index_hex) or {
			continue
		}

		index := decrypt_u64(enc_index, seed)

		if index >= u64(items.len) {
			return error('Invalid seed')
		}

		enc_chunk := hex.decode(enc_chunk_hex) or {
			continue
		}

		if index in chunks_map {
			return error('Duplicate index')
		}

		chunk := crypt_chunk(enc_chunk, index, seed)
		chunks_map[index] = chunk
	}

	if chunks_map.len == 0 {
		return error('No data found')
	}

	mut output_bytes := []u8{}
	for i := u64(0); i < u64(chunks_map.len); i++ {
		if i !in chunks_map {
			return error('Missing block')
		}
		output_bytes << chunks_map[i]
	}
	
	if output_file == '-' {
		mut out := os.stdout()
		out.write(output_bytes) or {
			return error('Write to stdout failed')
		}
	} else {
		os.write_bytes(output_file, output_bytes) or {
			return error('Write failed')
		}
		println('Success: Unpacked successfully')
	}
}

fn shred(target_dir string, iterations int, zero_final bool, remove bool, verbose bool) ! {
	if !os.exists(target_dir) || !os.is_dir(target_dir) {
		return error('Target is not a valid directory: ${target_dir}')
	}

	items := os.ls(target_dir) or { return err }
	mut target_files := []string{}
	for item in items {
		full_path := os.join_path(target_dir, item)
		if os.is_file(full_path) {
			target_files << full_path
		}
	}

	if target_files.len == 0 {
		if remove {
			os.rmdir(target_dir) or { return err }
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
				break
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
			os.rename(path, new_path) or {}
			path = new_path
			current_name = zero_name
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
				eprintln('Failed to remove file: ${path}')
			}
		}
	}

	if remove {
		if verbose {
			println('Removing parent container directory: ${target_dir}')
		}
		os.rmdir(target_dir) or {
			return error('Failed to remove root parent directory')
		}
	}

	println('Success: Shredding sequence completed.')
}
