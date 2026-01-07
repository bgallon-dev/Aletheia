package entropy

import "core:fmt"
import "core:math"
import "core:os"
import "core:strings"

get_entropy :: proc(window_string: string, m: int = 1) -> f64 {
    if len(window_string) == 0 {
        return 0
    }

    // Ensure the window is divisible by m for accurate grouping
    valid_length := (len(window_string) / m) * m
    window := window_string[:valid_length]

    if len(window) == 0 {
        return 0
    }

    // Count frequencies of each unique m-block
    counts := make(map[string]int)
    defer delete(counts)

    total_blocks := 0
    for i := 0; i < len(window); i += m {
        block := window[i:i + m]
        counts[block] = counts[block] + 1
        total_blocks += 1
    }

    // Apply Shannon Entropy Formula
    entropy: f64 = 0
    for _, count in counts {
        p := f64(count) / f64(total_blocks)
        entropy -= p * math.log2(p)
    }

    return entropy
}

read_file_as_binary_string :: proc(input_file: string) -> (string, bool) {
    data, ok := os.read_entire_file(input_file)
    if !ok {
        fmt.eprintln("Error: Could not read file:", input_file)
        return "", false
    }
    defer delete(data)

    builder := strings.builder_make()
    for byte in data {
        fmt.sbprintf(&builder, "%08b", byte)
    }

    return strings.clone(strings.to_string(builder)), true
}

calculate_entropic_barcode :: proc(
    binary_string: string,
    window_size: int,
    step_size: int,
    m: int = 1,
    verbose: bool = true,
) -> [dynamic]f64 {
    entropies := make([dynamic]f64)

    if len(binary_string) == 0 {
        return entropies
    }

    original_len := len(binary_string)

    // --- PADDING LOGIC (Equation 8) ---
    needed_len: int
    if original_len <= window_size {
        needed_len = window_size
    } else {
        steps := int(math.ceil(f64(original_len - window_size) / f64(step_size)))
        needed_len = (steps * step_size) + window_size
    }

    padding_needed := needed_len - original_len

    // Create padded string
    padded_builder := strings.builder_make()
    defer strings.builder_destroy(&padded_builder)

    strings.write_string(&padded_builder, binary_string)
    for _ in 0 ..< padding_needed {
        strings.write_byte(&padded_builder, '0')
    }

    padded_string := strings.to_string(padded_builder)

    if verbose {
        fmt.printfln("Processing: WS=%d, SS=%d, m=%d", window_size, step_size, m)
        fmt.printfln("Original Bits: %d | Padded Bits: %d", original_len, len(padded_string))
    }

    // --- SLIDING WINDOW LOGIC ---
    for i := 0; i <= len(padded_string) - window_size; i += step_size {
        window := padded_string[i:i + window_size]
        val := get_entropy(window, m)
        append(&entropies, val)
    }

    return entropies
}

main :: proc() {
    // Read file once
    binary_string, ok := read_file_as_binary_string("../../applsci-14-06297-v2.pdf")
    if !ok {
        return
    }
    defer delete(binary_string)

    // 1. "Jumping" (Compression) mode: SS = WS
    barcode_compressed := calculate_entropic_barcode(
        binary_string,
        window_size = 256,
        step_size = 256,
        m = 1,
    )
    defer delete(barcode_compressed)

    // 2. "Sliding" (High-Res) mode with m-blocks: SS < WS, m=2
    barcode_detailed := calculate_entropic_barcode(
        binary_string,
        window_size = 256,
        step_size = 64,
        m = 2,
    )
    defer delete(barcode_detailed)

    fmt.printfln("\nCompressed Barcode Length: %d", len(barcode_compressed))
    fmt.printfln("Detailed Barcode Length:   %d", len(barcode_detailed))
}
