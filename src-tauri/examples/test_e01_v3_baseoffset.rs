// Test EWF implementation with base offset support

use liblfx_lib::ewf::E01Handle;

fn main() {
    println!("\n========== Testing EWF with Base Offset Support ==========\n");
    
    let test_file = "/Users/terryreynolds/Downloads/4Dell Latitude CPi.E01";
    
    if !std::path::Path::new(test_file).exists() {
        eprintln!("Test file not found: {}", test_file);
        std::process::exit(1);
    }
    
    println!("Opening: {}\n", test_file);
    
    // Open the E01 file set
    let mut handle = match E01Handle::open(test_file) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to open E01: {}", e);
            std::process::exit(1);
        }
    };
    
    let chunk_count = handle.get_chunk_count();
    println!("\nTotal chunks: {}", chunk_count);
    
    // Try reading first 10 chunks
    println!("\nTesting first 10 chunks:");
    let mut success_count = 0;
    let mut fail_count = 0;
    
    for i in 0..10.min(chunk_count) {
        match handle.read_chunk(i) {
            Ok(data) => {
                success_count += 1;
                println!("  Chunk {}: OK ({} bytes)", i, data.len());
            }
            Err(e) => {
                fail_count += 1;
                println!("  Chunk {}: FAILED - {}", i, e);
            }
        }
    }
    
    println!("\nFirst 10: Success={}, Failed={}", success_count, fail_count);
    
    // Now read ALL chunks and compute MD5
    println!("\nReading all {} chunks and computing MD5...", chunk_count);
    
    use md5::Context;
    let mut hasher = Context::new();
    let mut success = 0;
    let mut failed = 0;
    let mut total_bytes = 0u64;
    
    let start = std::time::Instant::now();
    
    for i in 0..chunk_count {
        match handle.read_chunk(i) {
            Ok(data) => {
                // Print first 64 bytes of first chunk for comparison
                if i == 0 {
                    println!("First chunk data (first 64 bytes):");
                    for (j, byte) in data.iter().take(64).enumerate() {
                        if j % 16 == 0 {
                            print!("\n  {:04x}: ", j);
                        }
                        print!("{:02x} ", byte);
                    }
                    println!();
                }
                
                hasher.consume(&data);
                total_bytes += data.len() as u64;
                success += 1;
                
                // Debug: check for unexpected chunk sizes
                if data.len() != 32768 && i != chunk_count - 1 {
                    if i == 292 {
                        eprintln!("Chunk 292: size={}, expected=32768", data.len());
                    }
                    eprintln!("WARNING: Chunk {} has unexpected size: {} bytes", i, data.len());
                }
                
                if (i + 1) % 10000 == 0 {
                    println!("  Progress: {}/{} chunks ({:.1}%)", 
                            i + 1, chunk_count, 
                            (i + 1) as f64 / chunk_count as f64 * 100.0);
                }
            }
            Err(e) => {
                failed += 1;
                if failed <= 5 {
                    eprintln!("  Chunk {} failed: {}", i, e);
                }
            }
        }
    }
    
    let elapsed = start.elapsed();
    let result = hasher.compute();
    let md5_hex = format!("{:x}", result);
    
    println!("\n========== Results ==========");
    println!("Success: {} / {} ({:.1}%)", success, chunk_count, success as f64 / chunk_count as f64 * 100.0);
    println!("Failed:  {} / {} ({:.1}%)", failed, chunk_count, failed as f64 / chunk_count as f64 * 100.0);
    println!("Data read: {:.2} GB ({} bytes)", total_bytes as f64 / 1e9, total_bytes);
    println!("Time: {:.2} seconds", elapsed.as_secs_f64());
    println!("Throughput: {:.2} MB/s", total_bytes as f64 / elapsed.as_secs_f64() / 1e6);
    println!("\nMD5 (computed): {}", md5_hex);
    println!("MD5 (expected): aee4fcd9301c03b3b054623ca261959a");
    
    if md5_hex == "aee4fcd9301c03b3b054623ca261959a" {
        println!("\n✅ MD5 MATCH! Verification successful!");
    } else {
        println!("\n❌ MD5 MISMATCH! Verification failed!");
    }
}
