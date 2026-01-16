package main

import "core:fmt"
import "core:hash"
import "core:math"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:sync"
import "core:sys/windows"
import "core:thread"

// ============================================================================
// QUANTIZATION
// ============================================================================

Quantization_Version :: enum u8 {
	U8_LINEAR_V1,
	U8_LOG_V1,
}

CURRENT_QUANT_VERSION :: Quantization_Version.U8_LINEAR_V1

// Quantize f64 entropy to u8
// For byte entropy, max is 8.0 (log2(256))
// For m=2 byte blocks, max is 16.0 (log2(65536))
quantize_entropy :: proc(
	entropy: f64,
	max_entropy: f64,
	version: Quantization_Version = CURRENT_QUANT_VERSION,
) -> u8 {
	if entropy <= 0 {
		return 0
	}

	switch version {
	case .U8_LINEAR_V1:
		normalized := entropy / max_entropy
		return u8(min(normalized * 255.0, 255.0))
	case .U8_LOG_V1:
		// Log scaling: better resolution at low entropy values
		// log(1 + x) / log(1 + max) mapped to 0-255
		log_val := math.ln(1.0 + entropy)
		log_max := math.ln(1.0 + max_entropy)
		return u8(min((log_val / log_max) * 255.0, 255.0))
	}
	return 0
}

// ============================================================================
// ENTROPY COMPUTATION (Integer-indexed, no maps)
// ============================================================================

// Entropy over raw bytes using [256]u32 array - O(n) with no allocations
get_entropy_bytes :: proc(data: []u8) -> f64 {
	if len(data) == 0 {
		return 0
	}

	counts: [256]u32
	for byte in data {
		counts[byte] += 1
	}

	entropy: f64 = 0
	total := f64(len(data))
	for count in counts {
		if count > 0 {
			p := f64(count) / total
			entropy -= p * math.log2(p)
		}
	}
	return entropy
}

// Entropy over byte pairs (m=2) using [65536]u32 array
get_entropy_byte_pairs :: proc(data: []u8) -> f64 {
	if len(data) < 2 {
		return 0
	}

	counts: [65536]u32
	total_pairs: u32 = 0

	// Non-overlapping pairs
	for i := 0; i + 1 < len(data); i += 2 {
		key := u16(data[i]) << 8 | u16(data[i + 1])
		counts[key] += 1
		total_pairs += 1
	}

	if total_pairs == 0 {
		return 0
	}

	entropy: f64 = 0
	total := f64(total_pairs)
	for count in counts {
		if count > 0 {
			p := f64(count) / total
			entropy -= p * math.log2(p)
		}
	}
	return entropy
}

// ============================================================================
// REUSABLE SCRATCH SPACE FOR m=3,4 ENTROPY
// ============================================================================

// Scratch space that persists across calls - allocated once, reused many times
Entropy_Scratch :: struct {
	counts: map[u32]u32,
}

make_entropy_scratch :: proc() -> Entropy_Scratch {
	return Entropy_Scratch{counts = make(map[u32]u32)}
}

destroy_entropy_scratch :: proc(scratch: ^Entropy_Scratch) {
	delete(scratch.counts)
}

clear_map :: proc(m: ^map[$K]$V) {
	for key in m {
		delete_key(m, key)
	}
}

// General case for m=3,4 using reusable scratch space
get_entropy_m_blocks_with_scratch :: proc(data: []u8, m: int, scratch: ^Entropy_Scratch) -> f64 {
	if len(data) < m {
		return 0
	}

	// Clear the map but keep the allocated memory
	clear_map(&scratch.counts)

	total_blocks: u32 = 0
	for i := 0; i + m <= len(data); i += m {
		key: u32 = 0
		for j := 0; j < m; j += 1 {
			key = (key << 8) | u32(data[i + j])
		}
		scratch.counts[key] += 1
		total_blocks += 1
	}

	if total_blocks == 0 {
		return 0
	}

	entropy: f64 = 0
	total := f64(total_blocks)
	for _, count in scratch.counts {
		p := f64(count) / total
		entropy -= p * math.log2(p)
	}
	return entropy
}

// Standalone version (for one-off calls) - allocates internally
get_entropy_m_blocks_general :: proc(data: []u8, m: int) -> f64 {
	if len(data) < m {
		return 0
	}

	counts := make(map[u32]u32)
	defer delete(counts)

	total_blocks: u32 = 0
	for i := 0; i + m <= len(data); i += m {
		key: u32 = 0
		for j := 0; j < m; j += 1 {
			key = (key << 8) | u32(data[i + j])
		}
		counts[key] += 1
		total_blocks += 1
	}

	if total_blocks == 0 {
		return 0
	}

	entropy: f64 = 0
	total := f64(total_blocks)
	for _, count in counts {
		p := f64(count) / total
		entropy -= p * math.log2(p)
	}
	return entropy
}

// ============================================================================
// MEMORY-MAPPED FILE I/O (Handles files larger than RAM)
// ============================================================================

Mapped_File :: struct {
	data:        []u8,
	size:        int,
	// Windows handles
	file_handle: windows.HANDLE,
	map_handle:  windows.HANDLE,
}

// Memory-map a file - works for files of any size (50GB+)
// The OS pages data in/out as needed, never loads entire file into RAM
mmap_file :: proc(path: string) -> (Mapped_File, bool) {
	result: Mapped_File

	// Open file
	wide_path := windows.utf8_to_wstring(path)
	result.file_handle = windows.CreateFileW(
		wide_path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		nil,
	)

	if result.file_handle == windows.INVALID_HANDLE_VALUE {
		fmt.eprintln("Error: Could not open file:", path)
		return result, false
	}

	// Get file size
	file_size: windows.LARGE_INTEGER
	if !windows.GetFileSizeEx(result.file_handle, &file_size) {
		fmt.eprintln("Error: Could not get file size:", path)
		windows.CloseHandle(result.file_handle)
		return result, false
	}
	result.size = int(file_size)

	if result.size == 0 {
		fmt.eprintln("Error: File is empty:", path)
		windows.CloseHandle(result.file_handle)
		return result, false
	}

	// Create file mapping
	result.map_handle = windows.CreateFileMappingW(
		result.file_handle,
		nil,
		windows.PAGE_READONLY,
		0,
		0, // Map entire file
		nil,
	)

	if result.map_handle == nil {
		fmt.eprintln("Error: Could not create file mapping")
		windows.CloseHandle(result.file_handle)
		return result, false
	}

	// Map view into memory
	base_ptr := windows.MapViewOfFile(
		result.map_handle,
		windows.FILE_MAP_READ,
		0,
		0,
		0, // Map entire file
	)

	if base_ptr == nil {
		fmt.eprintln("Error: Could not map view of file")
		windows.CloseHandle(result.map_handle)
		windows.CloseHandle(result.file_handle)
		return result, false
	}

	result.data = mem.byte_slice(base_ptr, result.size)
	return result, true
}

// Unmap and close the file
munmap_file :: proc(mf: ^Mapped_File) {
	if mf.data != nil {
		windows.UnmapViewOfFile(raw_data(mf.data))
	}
	if mf.map_handle != nil {
		windows.CloseHandle(mf.map_handle)
	}
	if mf.file_handle != nil && mf.file_handle != windows.INVALID_HANDLE_VALUE {
		windows.CloseHandle(mf.file_handle)
	}
	mf.data = nil
	mf.size = 0
}

// Legacy function for small files (kept for compatibility)
read_file_bytes :: proc(input_file: string) -> ([]u8, bool) {
	data, ok := os.read_entire_file(input_file)
	if !ok {
		fmt.eprintln("Error: Could not read file:", input_file)
		return nil, false
	}
	return data, true
}

// ============================================================================
// BARCODE METADATA
// ============================================================================

Barcode_Metadata :: struct {
	window_size_bytes:   int,
	step_size_bytes:     int,
	m_block_size:        int,
	original_file_bytes: int,
	padded_bytes:        int,
	quantization:        Quantization_Version,
	barcode_len:         int,
}

// ============================================================================
// BARCODE RESULT - NOW WITH FIXED-SIZE SLICES (NOT DYNAMIC ARRAYS)
// ============================================================================

Barcode_Result :: struct {
	raw:      []f64, // Fixed-size slice - allocated once, indexed directly
	quant:    []u8, // Fixed-size slice - thread-safe random access
	metadata: Barcode_Metadata,
}

// ============================================================================
// PARALLEL WORKER CONTEXT
// ============================================================================

Worker_Context :: struct {
	// Input (read-only, shared across all threads)
	data:              []u8,
	window_size_bytes: int,
	step_size_bytes:   int,
	m:                 int,
	max_entropy:       f64,

	// Output (each thread writes to disjoint indices)
	raw:               []f64,
	quant:             []u8,

	// Work distribution
	start_window:      int,
	end_window:        int, // exclusive

	// Progress tracking (atomic)
	completed:         ^i64, // Changed from ^sync.Atomic(i64)
	total:             int,
}

// Worker procedure - processes a range of windows
worker_proc :: proc(ctx: ^Worker_Context) {
	// Each thread gets its own scratch space (no sharing!)
	scratch: Entropy_Scratch
	use_scratch := ctx.m == 3 || ctx.m == 4
	if use_scratch {
		scratch = make_entropy_scratch()
	}
	defer if use_scratch {destroy_entropy_scratch(&scratch)}

	for window_idx := ctx.start_window; window_idx < ctx.end_window; window_idx += 1 {
		// Calculate byte offset for this window
		byte_offset := window_idx * ctx.step_size_bytes
		window := ctx.data[byte_offset:byte_offset + ctx.window_size_bytes]

		// Compute entropy
		entropy: f64
		switch ctx.m {
		case 1:
			entropy = get_entropy_bytes(window)
		case 2:
			entropy = get_entropy_byte_pairs(window)
		case 3, 4:
			entropy = get_entropy_m_blocks_with_scratch(window, ctx.m, &scratch)
		case:
			entropy = get_entropy_bytes(window)
		}

		// Direct index write - NO APPEND, NO LOCK NEEDED
		// Each thread writes to different indices
		ctx.raw[window_idx] = entropy
		ctx.quant[window_idx] = quantize_entropy(entropy, ctx.max_entropy)

		// Atomic progress update
		sync.atomic_add(ctx.completed, 1)
	}
}

// ============================================================================
// PARALLEL ENTROPIC BARCODE
// ============================================================================

calculate_entropic_barcode_parallel :: proc(
	data: []u8,
	window_size_bytes: int = 64 * 1024,
	step_size_bytes: int = 16 * 1024,
	m: int = 1,
	num_threads: int = 0, // 0 = auto-detect
	verbose: bool = true,
) -> Barcode_Result {
	result: Barcode_Result

	if len(data) == 0 {
		return result
	}

	original_len := len(data)

	// =========================================================================
	// SMALL-FILE POLICY A: Clamp to one-window mode for files < window_size
	// =========================================================================
	ws := window_size_bytes
	ss := step_size_bytes

	// Validate parameters
	if ws <= 0 || ss <= 0 {
		if verbose {
			fmt.eprintln("Error: window_size and step_size must be positive")
		}
		return result
	}

	// Enforce step <= window
	if ss > ws {
		ss = ws
	}

	// If file is smaller than window, use entire file as one window
	if original_len < ws {
		ws = original_len
		ss = ws
	}

	// Now we can safely compute num_windows (guaranteed orig_len >= ws)
	num_windows := (original_len - ws) / ss + 1

	if num_windows == 0 {
		return result
	}

	// Max entropy depends on m
	max_entropy: f64
	switch m {
	case 1:
		max_entropy = 8.0
	case 2:
		max_entropy = 16.0
	case 3:
		max_entropy = 24.0
	case 4:
		max_entropy = 32.0
	case:
		max_entropy = 8.0
	}

	// Determine thread count
	actual_threads := num_threads
	if actual_threads <= 0 {
		// Get CPU count from OS, default to 8 if unavailable
		info: windows.SYSTEM_INFO
		windows.GetSystemInfo(&info)
		actual_threads = int(info.dwNumberOfProcessors)
		if actual_threads <= 0 {
			actual_threads = 8
		}
	}
	// Don't use more threads than windows
	actual_threads = min(actual_threads, num_windows)

	if verbose {
		fmt.printfln("Processing: WS=%d bytes, SS=%d bytes, m=%d", ws, ss, m)
		fmt.printfln(
			"File size: %d bytes (%.2f GB) | Windows: %d | Threads: %d",
			original_len,
			f64(original_len) / (1024 * 1024 * 1024),
			num_windows,
			actual_threads,
		)
	}

	// =========================================================================
	// THE FIX: Allocate fixed-size slices, not dynamic arrays
	// Each index is independent - threads can write in any order
	// =========================================================================
	result.raw = make([]f64, num_windows)
	result.quant = make([]u8, num_windows)

	// Atomic progress counter
	completed: i64 = 0
	sync.atomic_store(&completed, 0)

	// Divide work among threads
	windows_per_thread := num_windows / actual_threads
	remainder := num_windows % actual_threads

	// Create worker contexts and threads
	contexts := make([]Worker_Context, actual_threads)
	defer delete(contexts)

	threads := make([]^thread.Thread, actual_threads)
	defer delete(threads)

	current_window := 0
	for i := 0; i < actual_threads; i += 1 {
		// Distribute remainder windows to first threads
		extra := 1 if i < remainder else 0
		thread_windows := windows_per_thread + extra

		contexts[i] = Worker_Context {
			data              = data,
			window_size_bytes = ws,
			step_size_bytes   = ss,
			m                 = m,
			max_entropy       = max_entropy,
			raw               = result.raw,
			quant             = result.quant,
			start_window      = current_window,
			end_window        = current_window + thread_windows,
			completed         = &completed,
			total             = num_windows,
		}

		current_window += thread_windows
	}

	// Launch threads
	for i := 0; i < actual_threads; i += 1 {
		threads[i] = thread.create_and_start_with_poly_data(&contexts[i], worker_proc)
	}

	// Progress reporting while waiting
	if verbose && num_windows > 1000 {
		for {
			done := sync.atomic_load(&completed)
			if done >= i64(num_windows) {
				break
			}
			pct := f64(done) / f64(num_windows) * 100
			fmt.printf("\r  Progress: %.1f%% (%d/%d windows)", pct, done, num_windows)

			// Small sleep to avoid busy-waiting
			windows.Sleep(100)
		}
		fmt.println("\r  Progress: 100.0%                    ")
	}

	// Wait for all threads to complete
	for i := 0; i < actual_threads; i += 1 {
		thread.join(threads[i])
		thread.destroy(threads[i])
	}

	// Fill metadata
	result.metadata = Barcode_Metadata {
		window_size_bytes   = ws,
		step_size_bytes     = ss,
		m_block_size        = m,
		original_file_bytes = original_len,
		padded_bytes        = original_len,
		quantization        = CURRENT_QUANT_VERSION,
		barcode_len         = num_windows,
	}

	return result
}

// Sequential version (for comparison / small files)
calculate_entropic_barcode :: proc(
	data: []u8,
	window_size_bytes: int = 64 * 1024,
	step_size_bytes: int = 16 * 1024,
	m: int = 1,
	verbose: bool = true,
) -> Barcode_Result {
	result: Barcode_Result

	if len(data) == 0 {
		return result
	}

	original_len := len(data)

	// =========================================================================
	// SMALL-FILE POLICY A: Clamp to one-window mode for files < window_size
	// =========================================================================
	ws := window_size_bytes
	ss := step_size_bytes

	// Validate parameters
	if ws <= 0 || ss <= 0 {
		if verbose {
			fmt.eprintln("Error: window_size and step_size must be positive")
		}
		return result
	}

	// Enforce step <= window
	if ss > ws {
		ss = ws
	}

	// If file is smaller than window, use entire file as one window
	if original_len < ws {
		ws = original_len
		ss = ws
	}

	// Now we can safely compute num_windows (guaranteed orig_len >= ws)
	num_windows := (original_len - ws) / ss + 1

	if num_windows == 0 {
		return result
	}

	max_entropy: f64
	switch m {
	case 1:
		max_entropy = 8.0
	case 2:
		max_entropy = 16.0
	case 3:
		max_entropy = 24.0
	case 4:
		max_entropy = 32.0
	case:
		max_entropy = 8.0
	}

	if verbose {
		fmt.printfln("Processing: WS=%d bytes, SS=%d bytes, m=%d", ws, ss, m)
		fmt.printfln(
			"File size: %d bytes (%.2f GB) | Windows: %d (sequential)",
			original_len,
			f64(original_len) / (1024 * 1024 * 1024),
			num_windows,
		)
	}

	// THE FIX APPLIED HERE TOO: Fixed-size slices
	result.raw = make([]f64, num_windows)
	result.quant = make([]u8, num_windows)

	scratch: Entropy_Scratch
	use_scratch := m == 3 || m == 4
	if use_scratch {
		scratch = make_entropy_scratch()
	}
	defer if use_scratch {destroy_entropy_scratch(&scratch)}

	report_interval := max(num_windows / 100, 1)

	for window_idx := 0; window_idx < num_windows; window_idx += 1 {
		byte_offset := window_idx * ss
		window := data[byte_offset:byte_offset + ws]

		entropy: f64
		switch m {
		case 1:
			entropy = get_entropy_bytes(window)
		case 2:
			entropy = get_entropy_byte_pairs(window)
		case 3, 4:
			entropy = get_entropy_m_blocks_with_scratch(window, m, &scratch)
		case:
			entropy = get_entropy_bytes(window)
		}

		// Direct index write
		result.raw[window_idx] = entropy
		result.quant[window_idx] = quantize_entropy(entropy, max_entropy)

		if verbose && window_idx > 0 && window_idx % report_interval == 0 {
			pct := f64(window_idx) / f64(num_windows) * 100
			fmt.printf("\r  Progress: %.1f%%", pct)
		}
	}

	if verbose && num_windows > 100 {
		fmt.println("\r  Progress: 100.0%")
	}

	result.metadata = Barcode_Metadata {
		window_size_bytes   = ws,
		step_size_bytes     = ss,
		m_block_size        = m,
		original_file_bytes = original_len,
		padded_bytes        = original_len,
		quantization        = CURRENT_QUANT_VERSION,
		barcode_len         = num_windows,
	}

	return result
}

// ============================================================================
// BARCODE ROOT
// ============================================================================

// Simple FNV-1a hash of the quantized barcode
compute_barcode_root :: proc(quant: []u8) -> u64 {
	return hash.fnv64a(quant)
}

// ============================================================================
// CLEANUP
// ============================================================================

destroy_barcode :: proc(result: ^Barcode_Result) {
	delete(result.raw)
	delete(result.quant)
}

// ============================================================================
// BARCODE FILE FORMAT (Stable binary output)
// ============================================================================

// 32-byte header, then barcode bytes.
// Layout (little-endian):
//   0..7   : magic "ALBC0001" (8 bytes)
//   8..11  : window_size_bytes u32
//   12..15 : step_size_bytes   u32
//   16..19 : m_block_size      u32
//   20..23 : quant_version     u32
//   24..31 : barcode_len       u64
//   32..   : quantized barcode bytes (barcode_len bytes)

ALBC_MAGIC :: [8]u8{'A', 'L', 'B', 'C', '0', '0', '0', '1'}
ALBC_HEADER_SIZE :: 32

// New magic for extended format: "ALBC0002"
ALBC_MAGIC_EXTENDED :: [8]u8{'A', 'L', 'B', 'C', '0', '0', '0', '2'}

// Header layout adds:
//   32..39 : raw_data_offset u64 (0 if not present)
//   40..   : quantized bytes
//   ???..  : raw f64 array (optional)

put_u32_le :: proc(buf: []u8, off: int, v: u32) {
	buf[off + 0] = u8(v)
	buf[off + 1] = u8(v >> 8)
	buf[off + 2] = u8(v >> 16)
	buf[off + 3] = u8(v >> 24)
}

put_u64_le :: proc(buf: []u8, off: int, v: u64) {
	buf[off + 0] = u8(v)
	buf[off + 1] = u8(v >> 8)
	buf[off + 2] = u8(v >> 16)
	buf[off + 3] = u8(v >> 24)
	buf[off + 4] = u8(v >> 32)
	buf[off + 5] = u8(v >> 40)
	buf[off + 6] = u8(v >> 48)
	buf[off + 7] = u8(v >> 56)
}

get_u32_le :: proc(buf: []u8, off: int) -> u32 {
	return(
		u32(buf[off + 0]) |
		(u32(buf[off + 1]) << 8) |
		(u32(buf[off + 2]) << 16) |
		(u32(buf[off + 3]) << 24) \
	)
}

get_u64_le :: proc(buf: []u8, off: int) -> u64 {
	return(
		u64(buf[off + 0]) |
		(u64(buf[off + 1]) << 8) |
		(u64(buf[off + 2]) << 16) |
		(u64(buf[off + 3]) << 24) |
		(u64(buf[off + 4]) << 32) |
		(u64(buf[off + 5]) << 40) |
		(u64(buf[off + 6]) << 48) |
		(u64(buf[off + 7]) << 56) \
	)
}

starts_with_magic :: proc(buf: []u8) -> bool {
	if len(buf) < 8 {return false}

	// Create a local variable copy
	magic := ALBC_MAGIC

	for i := 0; i < 8; i += 1 {
		if buf[i] != magic[i] {return false}
	}
	return true
}

write_barcode_file :: proc(path: string, meta: Barcode_Metadata, quant: []u8) -> bool {
	if len(quant) == 0 {
		fmt.eprintln("Error: empty barcode; nothing to write")
		return false
	}

	total := ALBC_HEADER_SIZE + len(quant)
	out := make([]u8, total)

	// Create a local variable copy of the constant
	magic := ALBC_MAGIC // Now 'magic' is a variable with a real address

	// Magic - use the variable instead of the constant
	mem.copy(&out[0], &magic[0], 8)

	// Header fields
	put_u32_le(out, 8, u32(meta.window_size_bytes))
	put_u32_le(out, 12, u32(meta.step_size_bytes))
	put_u32_le(out, 16, u32(meta.m_block_size))
	put_u32_le(out, 20, u32(meta.quantization))
	put_u64_le(out, 24, u64(len(quant)))

	// Payload
	mem.copy(&out[ALBC_HEADER_SIZE], raw_data(quant), len(quant))

	ok := os.write_entire_file(path, out)
	if !ok {
		fmt.eprintln("Error: could not write barcode file:", path)
	}
	delete(out)
	return ok
}

// Add after write_barcode_file proc
write_barcode_file_v2 :: proc(
	path: string,
	meta: Barcode_Metadata,
	quant: []u8,
	raw: []f64,
) -> bool {
	if len(quant) == 0 {
		fmt.eprintln("Error: empty barcode; nothing to write")
		return false
	}

	// Header: 40 bytes for v2 (adds raw_data_offset)
	ALBC_V2_HEADER_SIZE :: 40

	raw_data_offset: u64 = 0
	raw_data_size := 0

	if len(raw) > 0 && len(raw) == len(quant) {
		raw_data_offset = u64(ALBC_V2_HEADER_SIZE + len(quant))
		raw_data_size = len(raw) * size_of(f64)
	}

	total := ALBC_V2_HEADER_SIZE + len(quant) + raw_data_size
	out := make([]u8, total)
	defer delete(out)

	// Magic "ALBC0002"
	magic := ALBC_MAGIC_EXTENDED
	mem.copy(&out[0], &magic[0], 8)

	// Header fields (same as v1 through offset 24)
	put_u32_le(out, 8, u32(meta.window_size_bytes))
	put_u32_le(out, 12, u32(meta.step_size_bytes))
	put_u32_le(out, 16, u32(meta.m_block_size))
	put_u32_le(out, 20, u32(meta.quantization))
	put_u64_le(out, 24, u64(len(quant)))

	// New v2 field: raw data offset (0 if no raw data)
	put_u64_le(out, 32, raw_data_offset)

	// Quantized payload
	mem.copy(&out[ALBC_V2_HEADER_SIZE], raw_data(quant), len(quant))

	// Raw f64 payload (if present)
	if raw_data_size > 0 {
		raw_bytes := mem.slice_to_bytes(raw)
		mem.copy(&out[int(raw_data_offset)], raw_data(raw_bytes), raw_data_size)
	}

	ok := os.write_entire_file(path, out)
	if !ok {
		fmt.eprintln("Error: could not write barcode file:", path)
	}
	return ok
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

main :: proc() {
	// Default values
	window_size_bytes := 64 * 1024
	step_size_bytes := 16 * 1024
	m := 1
	num_threads := 0
	verbose := true
	output_path := ""
	format_version := 1
	input_file := ""

	// Parse arguments
	args := os.args[1:]
	i := 0
	for i < len(args) {
		arg := args[i]

		switch arg {
		case "--help", "-h":
			fmt.println("Usage: entropy [options] <input_file>")
			fmt.println("Options:")
			fmt.println("  --window <size>    Set window size (default: 64KB)")
			fmt.println("  --step <size>      Set step size (default: 16KB)")
			fmt.println("  --m <value>        Set m value (1, 2, 3, or 4; default: 1)")
			fmt.println("  --threads <count>  Set number of threads (default: auto)")
			fmt.println("  --output <file>    Set output file path")
			fmt.println("  --format <version> Set format version (1 or 2; default: 1)")
			fmt.println("  --quiet, -q        Suppress output")
			fmt.println("  --verbose, -v      Enable verbose output")
			fmt.println("  --help, -h         Show this help message")
			os.exit(0)
		case "--window":
			if i + 1 < len(args) {
				if val, ok := strconv.parse_int(args[i + 1]); ok {
					window_size_bytes = val
				}
				i += 1
			}
		case "--step":
			if i + 1 < len(args) {
				if val, ok := strconv.parse_int(args[i + 1]); ok {
					step_size_bytes = val
				}
				i += 1
			}
		case "--m":
			if i + 1 < len(args) {
				if val, ok := strconv.parse_int(args[i + 1]); ok {
					m = val
					if m < 1 || m > 4 {
						fmt.eprintln("Error: m must be between 1 and 4")
						os.exit(1)
					}
				}
				i += 1
			}
		case "--threads":
			if i + 1 < len(args) {
				if val, ok := strconv.parse_int(args[i + 1]); ok {
					num_threads = val
				}
				i += 1
			}
		case "--output":
			if i + 1 < len(args) {
				output_path = args[i + 1]
				i += 1
			}
		case "--format", "-f":
			if i + 1 < len(args) {
				if val, ok := strconv.parse_int(args[i + 1]); ok {
					format_version = val
					if format_version < 1 || format_version > 2 {
						fmt.eprintln("Error: --format must be 1 or 2")
						os.exit(1)
					}
				}
				i += 1
			}
		case "--quiet", "-q":
			verbose = false
		case "--verbose", "-v":
			verbose = true
		case:
			// Non-option argument = input file
			// Accept any argument that doesn't start with '-' as input file
			if len(arg) > 0 && arg[0] != '-' {
				input_file = arg
			} else if len(arg) > 0 {
				fmt.eprintfln("Error: Unknown option: %s", arg)
				os.exit(2)
			}
		}

		i += 1
	}

	// Check for input file
	if input_file == "" {
		fmt.eprintln("Error: No input file specified")
		fmt.eprintln("Usage: entropy [options] <input_file>")
		os.exit(1)
	}

	// Default output path if not specified
	if output_path == "" {
		output_path = fmt.tprintf("%s.albc", input_file)
	}

	// Print settings
	if verbose {
		fmt.printfln("Input file: %s", input_file)
		fmt.printfln("Window size: %d bytes", window_size_bytes)
		fmt.printfln("Step size: %d bytes", step_size_bytes)
		fmt.printfln("m value: %d", m)
		fmt.printfln("Threads: %s", num_threads == 0 ? "auto" : fmt.tprintf("%d", num_threads))
		fmt.printfln("Output file: %s", output_path)
		fmt.printfln("Format version: %d", format_version)
	}

	// Memory-map the input file
	mf, ok := mmap_file(input_file)
	if !ok {
		fmt.eprintln("Error: Could not memory-map input file")
		os.exit(1)
	}
	defer munmap_file(&mf)

	// Check if input is already a barcode file
	if starts_with_magic(mf.data) {
		fmt.eprintln("Error: Input file appears to be an ALBC barcode file")
		os.exit(1)
	}

	// Compute the entropic barcode
	barcode_result := calculate_entropic_barcode_parallel(
		mf.data,
		window_size_bytes,
		step_size_bytes,
		m,
		num_threads,
		verbose,
	)
	defer destroy_barcode(&barcode_result)

	// Write output based on format version
	if format_version == 2 {
		ok = write_barcode_file_v2(
			output_path,
			barcode_result.metadata,
			barcode_result.quant,
			barcode_result.raw,
		)
		if verbose && ok {
			fmt.println("Wrote ALBC v2 (quantized + raw f64)")
		}
	} else {
		ok = write_barcode_file(output_path, barcode_result.metadata, barcode_result.quant)
		if verbose && ok {
			fmt.println("Wrote ALBC v1 (quantized only)")
		}
	}

	if !ok {
		os.exit(1)
	}
}
