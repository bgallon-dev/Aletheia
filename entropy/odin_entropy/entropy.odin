package entropy

import "core:fmt"
import "core:hash"
import "core:math"
import "core:mem"
import "core:os"
import "core:sync"
import "core:sys/windows"
import "core:thread"
import "core:strconv"

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
quantize_entropy :: proc(entropy: f64, max_entropy: f64, version: Quantization_Version = CURRENT_QUANT_VERSION) -> u8 {
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
    return Entropy_Scratch{
        counts = make(map[u32]u32),
    }
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
        0,  // Map entire file
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
        0,  // Map entire file
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
    raw:      []f64,  // Fixed-size slice - allocated once, indexed directly
    quant:    []u8,   // Fixed-size slice - thread-safe random access
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
    raw:   []f64,
    quant: []u8,
    
    // Work distribution
    start_window: int,
    end_window:   int,  // exclusive
    
    // Progress tracking (atomic)
    completed:    ^i64,  // Changed from ^sync.Atomic(i64)
    total:        int,
}

// Worker procedure - processes a range of windows
worker_proc :: proc(ctx: ^Worker_Context) {
    // Each thread gets its own scratch space (no sharing!)
    scratch: Entropy_Scratch
    use_scratch := ctx.m == 3 || ctx.m == 4
    if use_scratch {
        scratch = make_entropy_scratch()
    }
    defer if use_scratch { destroy_entropy_scratch(&scratch) }

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
    num_threads: int = 0,  // 0 = auto-detect
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
    case 1:  max_entropy = 8.0
    case 2:  max_entropy = 16.0
    case 3:  max_entropy = 24.0
    case 4:  max_entropy = 32.0
    case:    max_entropy = 8.0
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
        fmt.printfln("Processing: WS=%d bytes, SS=%d bytes, m=%d", 
                     ws, ss, m)
        fmt.printfln("File size: %d bytes (%.2f GB) | Windows: %d | Threads: %d",
                     original_len, f64(original_len) / (1024 * 1024 * 1024),
                     num_windows, actual_threads)
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

        contexts[i] = Worker_Context{
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
    result.metadata = Barcode_Metadata{
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
    case 1:  max_entropy = 8.0
    case 2:  max_entropy = 16.0
    case 3:  max_entropy = 24.0
    case 4:  max_entropy = 32.0
    case:    max_entropy = 8.0
    }

    if verbose {
        fmt.printfln("Processing: WS=%d bytes, SS=%d bytes, m=%d", 
                     ws, ss, m)
        fmt.printfln("File size: %d bytes (%.2f GB) | Windows: %d (sequential)",
                     original_len, f64(original_len) / (1024 * 1024 * 1024),
                     num_windows)
    }

    // THE FIX APPLIED HERE TOO: Fixed-size slices
    result.raw = make([]f64, num_windows)
    result.quant = make([]u8, num_windows)

    scratch: Entropy_Scratch
    use_scratch := m == 3 || m == 4
    if use_scratch {
        scratch = make_entropy_scratch()
    }
    defer if use_scratch { destroy_entropy_scratch(&scratch) }

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

    result.metadata = Barcode_Metadata{
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

ALBC_MAGIC :: [8]u8{'A','L','B','C','0','0','0','1'}
ALBC_HEADER_SIZE :: 32

// New magic for extended format: "ALBC0002"
ALBC_MAGIC_EXTENDED :: [8]u8{'A','L','B','C','0','0','0','2'}

// Header layout adds:
//   32..39 : raw_data_offset u64 (0 if not present)
//   40..   : quantized bytes
//   ???..  : raw f64 array (optional)

put_u32_le :: proc(buf: []u8, off: int, v: u32) {
    buf[off+0] = u8(v)
    buf[off+1] = u8(v >> 8)
    buf[off+2] = u8(v >> 16)
    buf[off+3] = u8(v >> 24)
}

put_u64_le :: proc(buf: []u8, off: int, v: u64) {
    buf[off+0] = u8(v)
    buf[off+1] = u8(v >> 8)
    buf[off+2] = u8(v >> 16)
    buf[off+3] = u8(v >> 24)
    buf[off+4] = u8(v >> 32)
    buf[off+5] = u8(v >> 40)
    buf[off+6] = u8(v >> 48)
    buf[off+7] = u8(v >> 56)
}

get_u32_le :: proc(buf: []u8, off: int) -> u32 {
    return u32(buf[off+0]) |
           (u32(buf[off+1]) << 8) |
           (u32(buf[off+2]) << 16) |
           (u32(buf[off+3]) << 24)
}

get_u64_le :: proc(buf: []u8, off: int) -> u64 {
    return u64(buf[off+0]) |
           (u64(buf[off+1]) << 8) |
           (u64(buf[off+2]) << 16) |
           (u64(buf[off+3]) << 24) |
           (u64(buf[off+4]) << 32) |
           (u64(buf[off+5]) << 40) |
           (u64(buf[off+6]) << 48) |
           (u64(buf[off+7]) << 56)
}

starts_with_magic :: proc(buf: []u8) -> bool {
    if len(buf) < 8 { return false }
    
    // Create a local variable copy
    magic := ALBC_MAGIC
    
    for i := 0; i < 8; i += 1 {
        if buf[i] != magic[i] { return false }
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
    magic := ALBC_MAGIC  // Now 'magic' is a variable with a real address
    
    // Magic - use the variable instead of the constant
    mem.copy(&out[0], &magic[0], 8)

    // Header fields
    put_u32_le(out, 8,  u32(meta.window_size_bytes))
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

Barcode_File :: struct {
    meta:  Barcode_Metadata,
    quant: []u8,
    _buf:  []u8, // keep underlying bytes alive if you choose not to copy
}

read_barcode_file :: proc(path: string) -> (Barcode_File, bool) {
    bf: Barcode_File

    data, ok := os.read_entire_file(path)
    if !ok {
        fmt.eprintln("Error: could not read barcode file:", path)
        return bf, false
    }

    if len(data) < ALBC_HEADER_SIZE || !starts_with_magic(data) {
        fmt.eprintln("Error: invalid barcode file (bad magic or too small):", path)
        delete(data)
        return bf, false
    }

    ws  := int(get_u32_le(data, 8))
    ss  := int(get_u32_le(data, 12))
    m   := int(get_u32_le(data, 16))
    qv  := Quantization_Version(get_u32_le(data, 20))
    bln := int(get_u64_le(data, 24))

    if bln < 0 || len(data) != ALBC_HEADER_SIZE + bln {
        fmt.eprintln("Error: invalid barcode file length:", path)
        delete(data)
        return bf, false
    }

    bf.meta = Barcode_Metadata{
        window_size_bytes   = ws,
        step_size_bytes     = ss,
        m_block_size        = m,
        original_file_bytes = 0,         // unknown from file; will be known at scan time
        padded_bytes        = 0,
        quantization        = qv,
        barcode_len         = bln,
    }

    bf._buf = data
    bf.quant = data[ALBC_HEADER_SIZE:] // slice into buffer (no copy)
    return bf, true
}

destroy_barcode_file :: proc(bf: ^Barcode_File) {
    delete(bf._buf)
    bf.quant = nil
}

// ============================================================================
// CLI ARG PARSING (minimal, dependency-free)
// ============================================================================

parse_i64 :: proc(s: string) -> (i64, bool) {
    if len(s) == 0 { return 0, false }
    sign: i64 = 1
    i := 0
    if s[0] == '-' {
        sign = -1
        i = 1
        if len(s) == 1 { return 0, false }
    }
    n: i64 = 0
    for ; i < len(s); i += 1 {
        c := s[i]
        if c < '0' || c > '9' { return 0, false }
        n = n*10 + i64(c - '0')
    }
    return n*sign, true
}

is_flag :: proc(s: string) -> bool {
    return len(s) >= 2 && s[0] == '-' && s[1] == '-'
}

// ============================================================================
// CLI COMMANDS
// ============================================================================

Scan_Opts :: struct {
    file_path: string,
    out_path:  string,
    window:    int,
    step:      int,
    m:         int,
    threads:   int,
    verbose:   bool,
    parallel:  bool,
    start_byte: int,  // NEW: byte range start (0 = from beginning)
    end_byte:   int,  // NEW: byte range end (0 = to end of file)
}

parse_scan_opts :: proc(args: []string) -> (Scan_Opts, bool) {
    opts := Scan_Opts{
        window     = 64 * 1024,
        step       = 16 * 1024,
        m          = 1,
        threads    = 0,
        verbose    = true,
        parallel   = true,
        start_byte = 0,  // NEW
        end_byte   = 0,  // NEW
    }

    for i := 0; i < len(args); i += 1 {
        a := args[i]

        if is_flag(a) {
            switch a {
            case "--window":
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.window = int(v); i += 1
            case "--step":
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.step = int(v); i += 1
            case "--m":
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.m = int(v); i += 1
            case "--threads":
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.threads = int(v); i += 1
            case "--out":
                if i+1 >= len(args) { return opts, false }
                opts.out_path = args[i+1]; i += 1
            case "--quiet":
                opts.verbose = false
            case "--sequential":
                opts.parallel = false
            case "--start":  // NEW
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.start_byte = int(v); i += 1
            case "--end":  // NEW
                if i+1 >= len(args) { return opts, false }
                v, ok := parse_i64(args[i+1]); if !ok { return opts, false }
                opts.end_byte = int(v); i += 1
            case:
                fmt.eprintln("Unknown flag:", a)
                return opts, false
            }
        } else {
            if opts.file_path == "" {
                opts.file_path = a
            } else {
                fmt.eprintln("Unexpected argument:", a)
                return opts, false
            }
        }
    }

    if opts.file_path == "" {
        fmt.eprintln("Error: missing <file>")
        return opts, false
    }

    // Stable output default
    if opts.out_path == "" {
        opts.out_path = fmt.tprintf("%s.albc", opts.file_path)
    }

    // For stable output in v1:
    if opts.m != 1 && opts.m != 2 {
        fmt.eprintln("Error: for stable output v1, use --m 1 or --m 2 (m>=3 uses map iteration).")
        return opts, false
    }

    return opts, true
}

cmd_scan :: proc(args: []string) -> int {
    opts, ok := parse_scan_opts(args)
    if !ok {
        print_usage()
        return 2
    }

    mf, mf_ok := mmap_file(opts.file_path)
    if !mf_ok { return 1 }
    defer munmap_file(&mf)

    // NEW: Apply byte range if specified
    data_slice := mf.data
    if opts.start_byte > 0 || opts.end_byte > 0 {
        start := opts.start_byte
        end := opts.end_byte
        
        // Validate range
        if start < 0 { start = 0 }
        if end <= 0 || end > len(mf.data) { end = len(mf.data) }
        if start >= end {
            fmt.eprintln("Error: invalid byte range: start >= end")
            return 1
        }
        
        data_slice = mf.data[start:end]
        
        if opts.verbose {
            fmt.printfln("Scanning byte range: [%d..%d) (%d bytes)", start, end, len(data_slice))
        }
    }

    res: Barcode_Result
    if opts.parallel {
        res = calculate_entropic_barcode_parallel(
            data_slice,  // Changed from mf.data
            window_size_bytes = opts.window,
            step_size_bytes   = opts.step,
            m                 = opts.m,
            num_threads       = opts.threads,
            verbose           = opts.verbose,
        )
    } else {
        res = calculate_entropic_barcode(
            data_slice,  // Changed from mf.data
            window_size_bytes = opts.window,
            step_size_bytes   = opts.step,
            m                 = opts.m,
            verbose           = opts.verbose,
        )
    }
    defer destroy_barcode(&res)

    if len(res.quant) == 0 {
        fmt.eprintln("Error: no windows produced (file too small for window_size?)")
        return 1
    }

    // Write stable barcode file
    write_ok := write_barcode_file(opts.out_path, res.metadata, res.quant)
    if !write_ok { return 1 }

    // Print summary + root
    root := compute_barcode_root(res.quant)

    fmt.printfln("OK: wrote %d windows to %s", len(res.quant), opts.out_path)
    fmt.printfln("Params: WS=%d SS=%d m=%d quant=%v", res.metadata.window_size_bytes, res.metadata.step_size_bytes, res.metadata.m_block_size, res.metadata.quantization)
    fmt.printfln("Barcode root (fnv64a): %016x", root)

    return 0
}

// ============================================================================
// DIFF COMMAND - Compare two barcode files
// ============================================================================

cmd_diff :: proc(args: []string) -> int {
    if len(args) < 2 {
        fmt.eprintln("Usage: entropy diff <file1.albc> <file2.albc> [options]")
        fmt.eprintln("")
        fmt.eprintln("Options:")
        fmt.eprintln("  --json       Output results as JSON")
        fmt.eprintln("  --threshold <f64>  Only report differences > threshold (default: 0)")
        return 2
    }

    file1_path := args[0]
    file2_path := args[1]
    
    json_output := false
    threshold: f64 = 0.0
    
    // Parse options
    i := 2
    for i < len(args) {
        arg := args[i]
        if arg == "--json" {
            json_output = true
            i += 1
        } else if arg == "--threshold" && i + 1 < len(args) {
            val, ok := parse_i64(args[i + 1])
            if ok {
                threshold = f64(val)
            }
            i += 2
        } else {
            fmt.eprintln("Unknown option:", arg)
            return 2
        }
    }

    // Read both barcode files
    bf1, ok1 := read_barcode_file(file1_path)
    if !ok1 {
        return 1
    }
    defer destroy_barcode_file(&bf1)

    bf2, ok2 := read_barcode_file(file2_path)
    if !ok2 {
        return 1
    }
    defer destroy_barcode_file(&bf2)

    // Check compatibility
    if bf1.meta.window_size_bytes != bf2.meta.window_size_bytes {
        fmt.eprintln("Error: Incompatible window sizes")
        fmt.eprintln("  File 1:", bf1.meta.window_size_bytes)
        fmt.eprintln("  File 2:", bf2.meta.window_size_bytes)
        return 1
    }

    if bf1.meta.step_size_bytes != bf2.meta.step_size_bytes {
        fmt.eprintln("Error: Incompatible step sizes")
        fmt.eprintln("  File 1:", bf1.meta.step_size_bytes)
        fmt.eprintln("  File 2:", bf2.meta.step_size_bytes)
        return 1
    }

    if bf1.meta.m_block_size != bf2.meta.m_block_size {
        fmt.eprintln("Error: Incompatible m block sizes")
        fmt.eprintln("  File 1:", bf1.meta.m_block_size)
        fmt.eprintln("  File 2:", bf2.meta.m_block_size)
        return 1
    }

    // Compare payloads
    n := min(len(bf1.quant), len(bf2.quant))
    if n == 0 {
        fmt.eprintln("Error: One or both barcodes are empty")
        return 1
    }

    total_diff: f64 = 0
    max_diff: f64 = 0
    max_diff_idx: int = 0
    sum_sq: f64 = 0
    num_above_threshold: int = 0

    for i := 0; i < n; i += 1 {
        val1 := f64(bf1.quant[i])
        val2 := f64(bf2.quant[i])
        d := math.abs(val1 - val2)
        
        total_diff += d
        sum_sq += d * d
        
        if d > max_diff {
            max_diff = d
            max_diff_idx = i
        }
        
        if d > threshold {
            num_above_threshold += 1
        }
    }

    avg := total_diff / f64(n)
    rms := math.sqrt(sum_sq / f64(n))
    
    // Normalize to [0, 1] range (quantized values are 0-255)
    avg_normalized := avg / 255.0
    rms_normalized := rms / 255.0
    max_normalized := max_diff / 255.0

    if json_output {
        // JSON output for scripting
        fmt.println("{")
        fmt.printf("  \"file1\": \"%s\",\n", file1_path)
        fmt.printf("  \"file2\": \"%s\",\n", file2_path)
        fmt.printf("  \"windows_compared\": %d,\n", n)
        fmt.printf("  \"avg_delta_raw\": %.4f,\n", avg)
        fmt.printf("  \"avg_delta_normalized\": %.6f,\n", avg_normalized)
        fmt.printf("  \"rms_delta_raw\": %.4f,\n", rms)
        fmt.printf("  \"rms_delta_normalized\": %.6f,\n", rms_normalized)
        fmt.printf("  \"max_delta_raw\": %.4f,\n", max_diff)
        fmt.printf("  \"max_delta_normalized\": %.6f,\n", max_normalized)
        fmt.printf("  \"max_delta_window\": %d,\n", max_diff_idx)
        fmt.printf("  \"windows_above_threshold\": %d,\n", num_above_threshold)
        fmt.printf("  \"threshold\": %.4f\n", threshold)
        fmt.println("}")
    } else {
        // Human-readable output
        fmt.println("\n=== Barcode Comparison ===")
        fmt.println("")
        fmt.println("File 1:", file1_path)
        fmt.println("File 2:", file2_path)
        fmt.println("")
        fmt.printf("Windows compared:  %d\n", n)
        fmt.println("")
        fmt.printf("Average ΔQ:        %.4f  (%.2f%% of range)\n", avg, avg_normalized * 100)
        fmt.printf("RMS ΔQ:            %.4f  (%.2f%% of range)\n", rms, rms_normalized * 100)
        fmt.printf("Max ΔQ:            %.4f  (%.2f%% of range) at window %d\n", 
                   max_diff, max_normalized * 100, max_diff_idx)
        
        if threshold > 0 {
            fmt.println("")
            fmt.printf("Windows > threshold: %d (%.2f%%)\n", 
                       num_above_threshold, f64(num_above_threshold) / f64(n) * 100)
        }
        fmt.println("")
    }

    return 0
}

print_usage :: proc() {
    fmt.println("Aletheia Entropy Scanner")
    fmt.println("")
    fmt.println("Usage:")
    fmt.println("  entropy scan <file> --window <bytes> --step <bytes> --m <1|2> --out <barcode.albc> [options]")
    fmt.println("  entropy diff <file1.albc> <file2.albc> [options]")
    fmt.println("")
    fmt.println("Scan options:")
    fmt.println("  --threads N       Number of threads (0 = auto)")
    fmt.println("  --quiet           Suppress verbose output")
    fmt.println("  --sequential      Disable parallel processing")
    fmt.println("  --start <byte>    Start scanning from byte offset (zoom scan)")
    fmt.println("  --end <byte>      End scanning at byte offset (zoom scan)")
    fmt.println("")
    fmt.println("Diff options:")
    fmt.println("  --json            Output results as JSON")
    fmt.println("  --threshold <f64> Only report differences > threshold (default: 0)")
}