use pdf2john::PdfHashExtractor;
use std::process;

fn usage() {
    eprintln!("Usage: pdf2john [-s|--show-filename] <pdf_files>...");
    eprintln!();
    eprintln!("Extract password hashes from encrypted PDFs for John the Ripper");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -s, --show-filename  Prefix output with the filename");
    eprintln!("  -h, --help           Print this help message");
}

fn main() {
    let mut show_filename = false;
    let mut pdf_files = Vec::new();

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-s" | "--show-filename" => show_filename = true,
            "-h" | "--help" => {
                usage();
                process::exit(0);
            }
            s if s.starts_with('-') => {
                eprintln!("Unknown option: {s}");
                eprintln!();
                usage();
                process::exit(1);
            }
            _ => pdf_files.push(arg),
        }
    }

    if pdf_files.is_empty() {
        usage();
        process::exit(1);
    }

    let mut had_error = false;

    for filename in &pdf_files {
        match PdfHashExtractor::from_file(filename) {
            Ok(extractor) => {
                let hash = extractor.format_hash();
                if show_filename {
                    println!("{filename}:{hash}");
                } else {
                    println!("{hash}");
                }
            }
            Err(e) => {
                eprintln!("{filename}: {e}");
                had_error = true;
            }
        }
    }

    if had_error {
        process::exit(1);
    }
}
