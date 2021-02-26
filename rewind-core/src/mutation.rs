
use std::{collections::BTreeSet, fmt::Display, io::BufWriter, str::FromStr};

use std::io::Write;
use std::convert::TryInto;

use serde::{Serialize, Deserialize};

use crate::{trace, fuzz::{Params, Strategy}, corpus::Corpus};

// #[derive(Debug, Default)]
// pub struct RoundRobinBalancer<T: Ord> {
//     pub items: BTreeSet<T>,
//     index: Arc<RwLock<usize>>,
// }

// impl <T: Ord> RoundRobinBalancer<T> {

//     pub fn insert(&mut self, item: T) {
//         self.items.insert(item);
//     }

//     pub fn rotate(&mut self) -> Option<&T> {
//         if self.items.is_empty() {
//             return None
//         }
//         let item = self.index.try_write();
//         let item = if let Ok(mut index) = item {
//             *index = (*index + 1) % self.items.len();

//             self.items.iter().nth(*index)
//         } else { None };
//         item
//     }

//     pub fn current(&self) -> Option<&T> {
//         if self.items.is_empty() {
//             return None
//         }
//         let item = self.index.try_write();
//         let item = if let Ok(index) = item {
//             self.items.iter().nth(*index)
//         } else { None };
//         item
//     }
// }

#[derive(Default)]
pub struct BasicStrategy {
    pub mutator: Mutator,
    pub coverage: BTreeSet<u64>,
    // balancer: RoundRobinBalancer<u64>,
    range: Option<Range>,
}

impl BasicStrategy {

    pub fn new(input_size: usize) -> Self {
        let mutator = Mutator::new().input_size(input_size);

        Self {
            mutator,
            coverage: BTreeSet::new(),
            // balancer: RoundRobinBalancer::default(),
            range: None,
        }
    }

    pub fn range(&mut self, range: Range) {
        let size = range.size();
        self.range = Some(range);
        self.mutator.input.resize(size, 0u8);
    }

}

// FIXME: should strategy own the corpus ?

impl Strategy for BasicStrategy {

    // FIXME: should have mutation hint too
    fn generate_new_input(&mut self, data: &mut [u8], corpus: &mut Corpus, _hint: &mut MutationHint) {
        // self.mutator.accessed = rules.offsets.iter().map(|o| *o as usize).collect();
        // self.mutator.immediate_values = rules.immediates.iter().map(|o| o.to_le_bytes().to_vec()).collect();

        // need to sync corpus
        // FIXME: impl round robin for corpus instead ?
        // corpus.members.iter().for_each(|(name, _data)| {
        //     self.balancer.insert(*name);
        // });

        // let to_remove: Vec<u64> = self.balancer.items.iter().filter(|&name| {
        //     !corpus.members.contains_key(name)
        // }).cloned().collect();

        // to_remove.iter().for_each(|name| {
        //     self.balancer.items.remove(name);
        // });

        let low = if let Some(range) = &self.range {
            range.low
        } else {
            0
        };

        let high = if let Some(range) = &self.range {
            range.high
        } else {
            self.mutator.input.len()
        };

        if let Some((_hash, entry)) = corpus.rotate() {
            // FIXME: use range 
            // input size should be range size
            // data should be rewritten with range
            self.mutator.clear();
            let data_len = data.len();
            data[..].copy_from_slice(&entry.data[..data_len]);
            self.mutator.input(&entry.data[low..high]);
            self.mutator.mutate(4);
            data[low..high].copy_from_slice(&self.mutator.input[..]);
        } else {
            self.mutator.mutate(4);
            data[low..high].copy_from_slice(&self.mutator.input[..]);
        }
    }

    // FIXME: use coverage to change corpus choice strategy ?
    fn check_new_coverage(&mut self, _params: &Params, trace: &mut trace::Trace) -> usize {
        let new = trace.seen.difference(&self.coverage).count();

        if new > 0 {

        } 

        self.coverage.append(&mut trace.seen);

        new
    }

    fn get_coverage(&mut self) -> usize {
        self.coverage.len()
    }

}

#[derive(Debug, Clone)]
pub struct Range {
    low: usize,
    high: usize,
}

impl Range {

    pub fn new() -> Self {
        Self {
            low: 0,
            high: 1
        }
    }

    pub fn low(mut self, low: usize) -> Self {
        self.low = low;
        self
    }

    pub fn high(mut self, high: usize) -> Self {
        self.high = high;
        self
    }

    pub fn size(&self) -> usize {
        self.high - self.low
    }

}

impl Default for Range {

    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for Range {

    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed: Vec<u16> = s
            // .trim_matches(|c| c == '[' || c == ']')
            .split('-')
            .filter_map(|n| n.trim().parse::<u16>().ok())
            .collect();

        if parsed.len() != 2 {
            return Err("bad range")
        }

        let range = Self {
            low: parsed[0] as usize,
            high: parsed[1] as usize
        };

        Ok(range)
    }
}

impl Display for Range {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.low, self.high)
    }
}

/// A basic random number generator based on xorshift64 with 64-bits of state
struct Rng {
    /// The RNG's seed and state
    seed: u64,

    /// If set, `rand_exp` behaves the same as `rand`
    exp_disabled: bool,
}

impl Rng {
    /// Generate a random number
    #[inline]
    fn next(&mut self) -> u64 {
        let val = self.seed;
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 17;
        self.seed ^= self.seed << 43;
        val
    }

    /// Generates a random number with uniform distribution in the range of
    /// [min, max]
    #[inline]
    fn rand(&mut self, min: usize, max: usize) -> usize {
        // Make sure the range is sane
        assert!(max >= min, "Bad range specified for rand()");

        // If there is no range, just return `min`
        if min == max {
            return min;
        }
        
        // If the range is unbounded, just return a random number
        if min == 0 && max == core::usize::MAX {
            return self.next() as usize;
        }

        // Pick a random number in the range
        min + (self.next() as usize % (max - min + 1))
    }
    
    /// Generates a random number with exponential distribution in the range of
    /// [min, max] with a worst case deviation from uniform of 0.5x. Meaning
    /// this will always return uniform at least half the time.
    #[inline]
    fn rand_exp(&mut self, min: usize, max: usize) -> usize {
        // If exponential random is disabled, fall back to uniform
        if self.exp_disabled {
            return self.rand(min, max);
        }

        if self.rand(0, 1) == 0 {
            // Half the time, provide uniform
            self.rand(min, max)
        } else {
            // Pick an exponentially difficult random number
            let x = self.rand(min, max);
            self.rand(min, x)
        }
    }
}


pub struct Mutator {

    pub input: Vec<u8>,
    rng: Rng,
    pub offsets: Vec<usize>,

}

impl Mutator {

    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            rng: Rng {
                seed:         0x12640367f4b7ea35,
                exp_disabled: true,
            },
            offsets: Vec::new(),

        }
    }

    /// Sets the seed for the internal RNG
    pub fn seed(mut self, seed: u64) -> Self {
        self.rng.seed = seed ^ 0x12640367f4b7ea35;
        self
    }

    /// Sets the maximum input size
    pub fn input_size(mut self, size: usize) -> Self {
        self.input.resize(size, 0u8);
        self
    }

    /// Sets the maximum input size
    pub fn clear(&mut self) {
        self.input.clear();
    }

    /// Sets the maximum input size
    pub fn input(&mut self, input: &[u8]) {
        self.input.extend(input);
    }

    /// Performs mutation of input
    pub fn mutate(&mut self, mutations: usize) {
        /// List of mutation strategies which do not require an input database
        const STRATEGIES: &[fn(&mut Mutator)] = &[
            Mutator::bit,
            Mutator::inc_byte,
            Mutator::dec_byte,
            Mutator::neg_byte,
            Mutator::add_sub,
            Mutator::rand,
            Mutator::magic,
        ];

        for _ in 0..mutations {
            // Pick a random mutation strategy
            let sel = self.rng.rand(0, STRATEGIES.len() - 1);
                
            // Get the strategy
            let strategy = STRATEGIES[sel];
            strategy(self);
        }

    }

    fn rand_offset(&mut self) -> usize {
        if !self.offsets.is_empty() {
            let offset = self.offsets[self.rng.rand_exp(0, self.offsets.len() - 1)];
            core::cmp::min(offset, self.input.len() - 1)
        } else if !self.input.is_empty() {
            self.rng.rand_exp(0, self.input.len() - 1)
        } else {
            0
        }
    }

    /// Add or subtract a random amount with a random endianness from a random
    /// size `u8` through `u64`
    fn add_sub(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick an offset to corrupt at
        let offset = self.rand_offset();

        let intsize = 1;

        // Determine the maximum number to add or subtract
        let range = 16;

        // Convert the range to a random number from [-range, range]
        let delta = self.rng.rand(0, range * 2) as i32 - range as i32;

        let tmp = u8::from_ne_bytes(self.input[offset..offset + intsize].try_into().unwrap());

        // Apply the delta, interpreting the bytes as a random
        // endianness
        let tmp = if self.rng.rand(0, 1) == 0 {
            tmp.wrapping_add(delta as u8)
        } else {
            tmp.swap_bytes().wrapping_add(delta as u8).swap_bytes()
        };

        // Write the new value out to the input
        self.input[offset..offset + intsize].copy_from_slice(&tmp.to_ne_bytes());

    }
    
    /// Overwrite the bytes in the input with `buf` at `offset`. If `buf`
    /// goes out of bounds of the input the `buf` will be truncated and the
    /// copy will stop.
    fn overwrite(&mut self, offset: usize, buf: &[u8]) {
        // Get the slice that we may overwrite
        let target = &mut self.input[offset..];

        // Get the length to overwrite
        let len = core::cmp::min(buf.len(), target.len());

        // Overwrite the bytes
        target[..len].copy_from_slice(&buf[..len]);
        
    }

    fn rand(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        let byte = self.rng.rand(0, 255) as u8;

        // Pick a random offset and length
        let offset = self.rand_offset();

        self.input[offset] = byte;
    }

    /// Write over the input with a random magic value
    fn magic(&mut self) {
        // Nothing to do on an empty input
        if self.input.is_empty() {
            return;
        }

        // Pick a random offset
        let offset = self.rand_offset();

        let index = self.rng.rand(0, MAGIC_VALUES.len()- 1);
        let magic_value = MAGIC_VALUES[index];
        // Overwrite it
        self.overwrite(offset, &magic_value);
    }

    fn bit(&mut self) {
        if self.input.is_empty() {
            return
        }

        let offset = self.rand_offset();
        self.input[offset] ^= 1u8 << self.rng.rand(0, 7);
    }

    fn inc_byte(&mut self) {
        if self.input.is_empty() {
            return
        }

        let offset = self.rand_offset();
        self.input[offset] = self.input[offset].wrapping_add(1);
    }

    fn dec_byte(&mut self) {
        if self.input.is_empty() {
            return
        }

        let offset = self.rand_offset();
        self.input[offset] = self.input[offset].wrapping_sub(1);
    }

    fn neg_byte(&mut self) {
        if self.input.is_empty() {
            return
        }

        let offset = self.rand_offset();
        self.input[offset] = !self.input[offset];
    }

}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
pub struct MutationHint {
    pub immediates: BTreeSet<u64>,
    pub offsets: BTreeSet<u64>,
    pub ranges: BTreeSet<(usize, usize)>
}

impl MutationHint {

    pub fn new() -> Self {
        Self {
            immediates: BTreeSet::new(),
            offsets: BTreeSet::new(),
            ranges: BTreeSet::new()
        }
    }

    pub fn save<P>(&self, path: P) -> Result<(), crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self, crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl Default for MutationHint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use crate::mutation::*;

    #[test]
    fn test_simple() {
        let mut mutator = Mutator::new().input_size(0x100);
        mutator.mutate(1);
    }

    #[test]
    fn test_rand() {
        let mut mutator = Mutator::new();
        assert_eq!(mutator.rand_offset(), 0);

        let mut mutator = Mutator::new().input_size(0x10);
        assert_eq!(mutator.rand_offset(), 5);
        assert_eq!(mutator.rand_offset(), 13);
        assert_eq!(mutator.rand_offset(), 5);
        assert_eq!(mutator.rand_offset(), 2);
        assert_eq!(mutator.rand_offset(), 15);
        assert_eq!(mutator.rand_offset(), 12);

        let mut mutator = Mutator::new().input_size(0x10).seed(1);
        assert_eq!(mutator.rand_offset(), 4);
        assert_eq!(mutator.rand_offset(), 12);
        assert_eq!(mutator.rand_offset(), 4);
        assert_eq!(mutator.rand_offset(), 3);
        assert_eq!(mutator.rand_offset(), 12);
        assert_eq!(mutator.rand_offset(), 15);


        mutator.mutate(1);
    }

    #[test]
    fn test_offsets() {
        let mut mutator = Mutator::new().input_size(0x10);
        mutator.offsets.push(4);

        for  _ in 0..1000 {
            assert_eq!(mutator.rand_offset(), 4);
        }

    }

    #[test]
    fn test_mutate() {
        let mut mutator = Mutator::new().input_size(0x10);
        let input = mutator.input.clone();

        mutator.mutate(1);

        assert_ne!(input, mutator.input);

    }

    #[test]
    fn test_mutate2() {
        let mut counter = 0;
        let mut mutator = Mutator::new().input_size(0x60);

        loop {
            counter += 1;
            mutator.mutate(1);

            if mutator.input[0x30] == 0x38 {
                break
            }
        }

        assert_eq!(mutator.input[0x30], 0x38);
        assert_eq!(counter, 3641);

        loop {
            counter += 1;
            mutator.mutate(1);

            if mutator.input[0x10] == 0x80 {
                break
            }
        }

        assert_eq!(mutator.input[0x10], 0x80);
        assert_eq!(counter, 7705);


    }
}

pub const MAGIC_VALUES: &[&[u8]] = &[
    b"\x00",
    b"\x01",
    b"\x02",
    b"\x03",
    b"\x04",
    b"\x05",
    b"\x06",
    b"\x07",
    b"\x08",
    b"\x09",
    b"\x0a",
    b"\x0b",
    b"\x0c",
    b"\x0d",
    b"\x0e",
    b"\x0f",
    b"\x10",
    b"\x20",
    b"\x40",
    b"\x7e",
    b"\x7f",
    b"\x80",
    b"\x81",
    b"\xc0",
    b"\xfe",
    b"\xff",
    b"\x00\x00",
    b"\x01\x01",
    b"\x80\x80",
    b"\xff\xff",
    b"\x00\x01",
    b"\x00\x02",
    b"\x00\x03",
    b"\x00\x04",
    b"\x00\x05",
    b"\x00\x06",
    b"\x00\x07",
    b"\x00\x08",
    b"\x00\x09",
    b"\x00\x0a",
    b"\x00\x0b",
    b"\x00\x0c",
    b"\x00\x0d",
    b"\x00\x0e",
    b"\x00\x0f",
    b"\x00\x10",
    b"\x00\x20",
    b"\x00\x40",
    b"\x00\x7e",
    b"\x00\x7f",
    b"\x00\x80",
    b"\x00\x81",
    b"\x00\xc0",
    b"\x00\xfe",
    b"\x00\xff",
    b"\x7e\xff",
    b"\x7f\xff",
    b"\x80\x00",
    b"\x80\x01",
    b"\xff\xfe",
    b"\x00\x00",
    b"\x01\x00",
    b"\x02\x00",
    b"\x03\x00",
    b"\x04\x00",
    b"\x05\x00",
    b"\x06\x00",
    b"\x07\x00",
    b"\x08\x00",
    b"\x09\x00",
    b"\x0a\x00",
    b"\x0b\x00",
    b"\x0c\x00",
    b"\x0d\x00",
    b"\x0e\x00",
    b"\x0f\x00",
    b"\x10\x00",
    b"\x20\x00",
    b"\x40\x00",
    b"\x7e\x00",
    b"\x7f\x00",
    b"\x80\x00",
    b"\x81\x00",
    b"\xc0\x00",
    b"\xfe\x00",
    b"\xff\x00",
    b"\xff\x7e",
    b"\xff\x7f",
    b"\x00\x80",
    b"\x01\x80",
    b"\xfe\xff",
    b"\x00\x00\x00\x00",
    b"\x01\x01\x01\x01",
    b"\x80\x80\x80\x80",
    b"\xff\xff\xff\xff",
    b"\x00\x00\x00\x01",
    b"\x00\x00\x00\x02",
    b"\x00\x00\x00\x03",
    b"\x00\x00\x00\x04",
    b"\x00\x00\x00\x05",
    b"\x00\x00\x00\x06",
    b"\x00\x00\x00\x07",
    b"\x00\x00\x00\x08",
    b"\x00\x00\x00\x09",
    b"\x00\x00\x00\x0a",
    b"\x00\x00\x00\x0b",
    b"\x00\x00\x00\x0c",
    b"\x00\x00\x00\x0d",
    b"\x00\x00\x00\x0e",
    b"\x00\x00\x00\x0f",
    b"\x00\x00\x00\x10",
    b"\x00\x00\x00\x20",
    b"\x00\x00\x00\x40",
    b"\x00\x00\x00\x7e",
    b"\x00\x00\x00\x7f",
    b"\x00\x00\x00\x80",
    b"\x00\x00\x00\x81",
    b"\x00\x00\x00\xc0",
    b"\x00\x00\x00\xfe",
    b"\x00\x00\x00\xff",
    b"\x7e\xff\xff\xff",
    b"\x7f\xff\xff\xff",
    b"\x80\x00\x00\x00",
    b"\x80\x00\x00\x01",
    b"\xff\xff\xff\xfe",
    b"\x00\x00\x00\x00",
    b"\x01\x00\x00\x00",
    b"\x02\x00\x00\x00",
    b"\x03\x00\x00\x00",
    b"\x04\x00\x00\x00",
    b"\x05\x00\x00\x00",
    b"\x06\x00\x00\x00",
    b"\x07\x00\x00\x00",
    b"\x08\x00\x00\x00",
    b"\x09\x00\x00\x00",
    b"\x0a\x00\x00\x00",
    b"\x0b\x00\x00\x00",
    b"\x0c\x00\x00\x00",
    b"\x0d\x00\x00\x00",
    b"\x0e\x00\x00\x00",
    b"\x0f\x00\x00\x00",
    b"\x10\x00\x00\x00",
    b"\x20\x00\x00\x00",
    b"\x40\x00\x00\x00",
    b"\x7e\x00\x00\x00",
    b"\x7f\x00\x00\x00",
    b"\x80\x00\x00\x00",
    b"\x81\x00\x00\x00",
    b"\xc0\x00\x00\x00",
    b"\xfe\x00\x00\x00",
    b"\xff\x00\x00\x00",
    b"\xff\xff\xff\x7e",
    b"\xff\xff\xff\x7f",
    b"\x00\x00\x00\x80",
    b"\x01\x00\x00\x80",
    b"\xfe\xff\xff\xff",
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x01\x01\x01\x01\x01\x01\x01\x01",
    b"\x80\x80\x80\x80\x80\x80\x80\x80",
    b"\xff\xff\xff\xff\xff\xff\xff\xff",
    b"\x00\x00\x00\x00\x00\x00\x00\x01",
    b"\x00\x00\x00\x00\x00\x00\x00\x02",
    b"\x00\x00\x00\x00\x00\x00\x00\x03",
    b"\x00\x00\x00\x00\x00\x00\x00\x04",
    b"\x00\x00\x00\x00\x00\x00\x00\x05",
    b"\x00\x00\x00\x00\x00\x00\x00\x06",
    b"\x00\x00\x00\x00\x00\x00\x00\x07",
    b"\x00\x00\x00\x00\x00\x00\x00\x08",
    b"\x00\x00\x00\x00\x00\x00\x00\x09",
    b"\x00\x00\x00\x00\x00\x00\x00\x0a",
    b"\x00\x00\x00\x00\x00\x00\x00\x0b",
    b"\x00\x00\x00\x00\x00\x00\x00\x0c",
    b"\x00\x00\x00\x00\x00\x00\x00\x0d",
    b"\x00\x00\x00\x00\x00\x00\x00\x0e",
    b"\x00\x00\x00\x00\x00\x00\x00\x0f",
    b"\x00\x00\x00\x00\x00\x00\x00\x10",
    b"\x00\x00\x00\x00\x00\x00\x00\x20",
    b"\x00\x00\x00\x00\x00\x00\x00\x40",
    b"\x00\x00\x00\x00\x00\x00\x00\x7e",
    b"\x00\x00\x00\x00\x00\x00\x00\x7f",
    b"\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\x00\x00\x00\x00\x00\x00\x00\x81",
    b"\x00\x00\x00\x00\x00\x00\x00\xc0",
    b"\x00\x00\x00\x00\x00\x00\x00\xfe",
    b"\x00\x00\x00\x00\x00\x00\x00\xff",
    b"\x7e\xff\xff\xff\xff\xff\xff\xff",
    b"\x7f\xff\xff\xff\xff\xff\xff\xff",
    b"\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x80\x00\x00\x00\x00\x00\x00\x01",
    b"\xff\xff\xff\xff\xff\xff\xff\xfe",
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x01\x00\x00\x00\x00\x00\x00\x00",
    b"\x02\x00\x00\x00\x00\x00\x00\x00",
    b"\x03\x00\x00\x00\x00\x00\x00\x00",
    b"\x04\x00\x00\x00\x00\x00\x00\x00",
    b"\x05\x00\x00\x00\x00\x00\x00\x00",
    b"\x06\x00\x00\x00\x00\x00\x00\x00",
    b"\x07\x00\x00\x00\x00\x00\x00\x00",
    b"\x08\x00\x00\x00\x00\x00\x00\x00",
    b"\x09\x00\x00\x00\x00\x00\x00\x00",
    b"\x0a\x00\x00\x00\x00\x00\x00\x00",
    b"\x0b\x00\x00\x00\x00\x00\x00\x00",
    b"\x0c\x00\x00\x00\x00\x00\x00\x00",
    b"\x0d\x00\x00\x00\x00\x00\x00\x00",
    b"\x0e\x00\x00\x00\x00\x00\x00\x00",
    b"\x0f\x00\x00\x00\x00\x00\x00\x00",
    b"\x10\x00\x00\x00\x00\x00\x00\x00",
    b"\x20\x00\x00\x00\x00\x00\x00\x00",
    b"\x40\x00\x00\x00\x00\x00\x00\x00",
    b"\x7e\x00\x00\x00\x00\x00\x00\x00",
    b"\x7f\x00\x00\x00\x00\x00\x00\x00",
    b"\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x81\x00\x00\x00\x00\x00\x00\x00",
    b"\xc0\x00\x00\x00\x00\x00\x00\x00",
    b"\xfe\x00\x00\x00\x00\x00\x00\x00",
    b"\xff\x00\x00\x00\x00\x00\x00\x00",
    b"\xff\xff\xff\xff\xff\xff\xff\x7e",
    b"\xff\xff\xff\xff\xff\xff\xff\x7f",
    b"\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\x01\x00\x00\x00\x00\x00\x00\x80",
    b"\xfe\xff\xff\xff\xff\xff\xff\xff",
];


