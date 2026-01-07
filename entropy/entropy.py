import math

def get_entropy(window_string, m=1):
    """
    Calculates Shannon Entropy for a window using m-block segments.
    
    Args:
        window_string: Binary string to calculate entropy for
        m: Block size for grouping bits (default=1 for single bits)
    
    Returns:
        float: Entropy value (max = m bits)
    """
    if len(window_string) == 0:
        return 0
    
    # Ensure the window is divisible by m for accurate grouping
    valid_length = (len(window_string) // m) * m
    window_string = window_string[:valid_length]
    
    if len(window_string) == 0:
        return 0

    # 1. Group bits into m-blocks (e.g., "1100" with m=2 -> ["11", "00"])
    m_blocks = [window_string[i:i+m] for i in range(0, len(window_string), m)]
    
    total_blocks = len(m_blocks)
    
    # 2. Count frequencies of each unique block
    counts = {}
    for block in m_blocks:
        counts[block] = counts.get(block, 0) + 1
        
    # 3. Apply Shannon Entropy Formula (Eq 3 in paper)
    entropy = 0
    for block in counts:
        p = counts[block] / total_blocks
        entropy -= p * math.log2(p)
        
    return entropy

def calculate_entropic_barcode(input_file, window_size, step_size, m=1, verbose=True):
    """
    Calculate entropic barcode over a binary representation of a file.
    
    Args:
        input_file: Path to the input file
        window_size: Size of the window (WS) in bits
        step_size: Step size (SS) for sliding. 1 <= SS <= WS
        m: Block size for entropy calculation
        verbose: Print processing info (default=True)
    
    Returns:
        list[float]: List of entropy values for each window
    """
    with open(input_file, "rb") as rb:
        data = rb.read()
        binary_string = ''.join(format(byte, '08b') for byte in data)

    original_len = len(binary_string)
    
    # --- PADDING LOGIC (Equation 8) ---
    if original_len <= window_size:
        needed_len = window_size
    else:
        steps = math.ceil((original_len - window_size) / step_size)
        needed_len = (steps * step_size) + window_size
        
    padding_needed = needed_len - original_len
    binary_string += '0' * padding_needed

    if verbose:
        print(f"Processing: WS={window_size}, SS={step_size}, m={m}")
        print(f"Original Bits: {original_len} | Padded Bits: {len(binary_string)}")

    # --- SLIDING WINDOW LOGIC ---
    entropies = []
    
    for i in range(0, len(binary_string) - window_size + 1, step_size):
        window = binary_string[i : i + window_size]
        val = get_entropy(window, m)
        entropies.append(val)

    return entropies


if __name__ == "__main__":
    # Example Usage (only runs when executed directly)
    
    # 1. "Jumping" (Compression) mode: SS = WS
    barcode_compressed = calculate_entropic_barcode(
        "./applsci-14-06297-v2.pdf", 
        window_size=256, 
        step_size=256, 
        m=1
    )

    # 2. "Sliding" (High-Res) mode with m-blocks: SS < WS, m=2
    barcode_detailed = calculate_entropic_barcode(
        "./applsci-14-06297-v2.pdf", 
        window_size=256, 
        step_size=64, 
        m=2
    )

    print(f"\nCompressed Barcode Length: {len(barcode_compressed)}")
    print(f"Detailed Barcode Length:   {len(barcode_detailed)}")