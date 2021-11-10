use std::io;
use compress_tools::*;
use std::fs::File;
use std::path::Path;

fn main() {
    let mut source = File::open ("test.7z");
    let dest = Path::new("/tmp/dest");

    uncompress_archive(&mut source, &dest, Ownership::Preserve);
}
