// Simple E01 test example
use liblfx_lib::ewf;

fn main() {
    let path = "/Users/terryreynolds/Downloads/4Dell Latitude CPi.E01";
    println!("Testing E01 info for: {}", path);
    
    match ewf::info(path) {
        Ok(info) => {
            println!("Success!");
            println!("Segments: {}", info.segment_count);
            println!("Chunks: {}", info.chunk_count);
            println!("Sectors: {}", info.sector_count);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
