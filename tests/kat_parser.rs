use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

#[derive(Debug)]
pub struct KatTestCase {
    pub count: usize,
    pub seed: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub ct: Vec<u8>,
    pub ss: Vec<u8>,
}

pub fn parse_kat_rsp_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<KatTestCase>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut test_cases = Vec::new();
    let mut current_case = None;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("count = ") {
            if let Some(case) = current_case.take() {
                test_cases.push(case);
            }
            let count: usize = line[8..].parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            current_case = Some(KatTestCase { count, seed: Vec::new(), pk: Vec::new(), sk: Vec::new(), ct: Vec::new(), ss: Vec::new() });
        } else if let Some(ref mut case) = current_case {
            let parts: Vec<&str> = line.splitn(2, " = ").collect();
            if parts.len() != 2 {
                continue;
            }
            let key = parts[0].trim();
            let value = parts[1].trim();
            let bytes = hex::decode(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            match key {
                "seed" => case.seed = bytes,
                "pk" => case.pk = bytes,
                "sk" => case.sk = bytes,
                "ct" => case.ct = bytes,
                "ss" => case.ss = bytes,
                _ => {}
            }
        }
    }

    if let Some(case) = current_case {
        test_cases.push(case);
    }

    Ok(test_cases)
}
