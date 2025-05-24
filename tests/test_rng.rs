use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

pub struct TestRng {
    seed: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    pos: usize,
}

impl TestRng {
    pub fn new(seed: &[u8]) -> Self {
        TestRng {
            seed: seed.to_vec(),
            counter: 0,
            buffer: vec![0u8; 1024],
            pos: 1024, // Force refill on first use
        }
    }

    fn refill(&mut self) {
        let mut shake = Shake128::default();
        shake.update(&self.seed);
        shake.update(&self.counter.to_le_bytes());
        shake.finalize_xof_into(&mut self.buffer);
        self.pos = 0;
        self.counter = self.counter.wrapping_add(1);
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut remaining = dest.len();
        let mut dest_pos = 0;

        while remaining > 0 {
            if self.pos >= self.buffer.len() {
                self.refill();
            }

            let to_copy = (self.buffer.len() - self.pos).min(remaining);
            dest[dest_pos..dest_pos + to_copy].copy_from_slice(&self.buffer[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            dest_pos += to_copy;
            remaining -= to_copy;
        }
    }
}
