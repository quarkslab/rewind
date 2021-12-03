
//! Mutation

use std::{collections::BTreeSet, convert::TryFrom, io::BufWriter};

use std::io::Write;
use std::convert::TryInto;

use rand::prelude::*;

use serde::{Serialize, Deserialize};

use crate::{corpus::Corpus, error::GenericError, fuzz::{Params, Strategy}, trace};

/// Basic fuzzing strategy
#[derive(Default)]
pub struct BasicStrategy  {
    /// Mutator used
    pub mutator: Mutator,
    /// Coverage
    pub coverage: BTreeSet<u64>,
}

impl BasicStrategy {

    /// Constructor
    pub fn new(mutator: Mutator) -> Self {
        // FIXME: to own or not the mutator, that's the question... 
        Self {
            mutator,
            coverage: BTreeSet::new(),
        }
    }

}

// FIXME: should strategy own the corpus ?

impl Strategy for BasicStrategy {

    // FIXME: better corpus rotation? 
    fn generate_new_input(&mut self, data: &mut [u8], corpus: &mut Corpus, _hint: &mut MutationHint) {
        if let Some((_hash, entry)) = corpus.rotate() {
            let data_len = data.len();
            data[..].copy_from_slice(&entry.data[..data_len]);
        }
        self.mutator.mutate(data);
    }

    // FIXME: use coverage to change corpus choice strategy ?
    fn check_new_coverage(&mut self, _params: &Params, trace: &mut trace::Trace) -> usize {
        let new = trace.seen.difference(&self.coverage).count();
        self.coverage.append(&mut trace.seen);
        new
    }

    fn get_coverage(&mut self) -> usize {
        self.coverage.len()
    }

}

/// Hints to guide mutator
#[derive(Serialize, Deserialize)]
pub struct MutationHint {
    /// Constant values found by disassembling instructions
    pub immediates: BTreeSet<u64>,
    /// Accessed offsets from input
    pub offsets: BTreeSet<u64>,
}

impl MutationHint {

    /// Constructor
    pub fn new() -> Self {
        Self {
            immediates: BTreeSet::new(),
            offsets: BTreeSet::new(),
        }
    }

    /// Serialize to json and save to disk 
    pub fn save<P>(&self, path: P) -> Result<(), crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Load from disk and deserialize
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

/// Field
pub trait Field {
    /// Name
    fn name(&self) -> &str;

    /// Offset
    fn offset(&self) -> usize;

    /// Size
    fn size(&self) -> usize;

    /// Mutate
    fn mutate(&self, data: &mut [u8]);

}

// FIXME: for U8, U16, U32, U64 learn to use macro...

struct U8 {
    name: String,
    offset: usize,
    constraints: Option<FieldConstraint>,

}

impl U8 {
    fn new(name: String, offset: usize, constraints: Option<FieldConstraint>) -> Self {
        Self {
            name,
            offset,
            constraints
        }
    }

    fn add(&self, data: &mut [u8]) {
        let value = data[self.offset];

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_add(delta);

        data[self.offset] = value;
    }

    fn sub(&self, data: &mut [u8]) {
        let value = data[self.offset];

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_sub(delta);

        data[self.offset] = value;
    }

    fn rand(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let value = if let Some(constraints) = self.constraints.as_ref() {
            match (constraints.min, constraints.max) {
                (None, None) => {
                    rng.gen::<u8>()
                }
                (Some(min), None) => {
                    rng.gen_range(min as u8..u8::MAX)
                }
                (None, Some(max)) => {
                    rng.gen_range(u8::MIN..max as u8)
                }
                (Some(min), Some(max)) => {
                    rng.gen_range(min..max) as u8
                }
            }
        } else {
            rng.gen()
        };
 
        data[self.offset] = value;
    }

    fn magic(&self, data: &mut [u8]) {
        let magic_values = [
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
        ];
        let mut rng = thread_rng();
        if let Some(magic) = magic_values.choose(&mut rng) {
            data[self.offset] = magic[0];
        }
    }
}

impl Field for U8 {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        1
    }

    fn mutate(&self, data: &mut [u8]) {
        if data.get(self.offset).is_none() {
            return
        }

        const STRATEGIES: &[fn(&U8, &mut [u8])] = &[
            U8::add,
            U8::sub,
            U8::rand,
            U8::magic,
        ];

        if let Some(constraints) = self.constraints.as_ref() {
            if let Some(value) = constraints.value {
                data[self.offset] = value as u8;
                return
            }

            if let (Some(_min), Some(_max)) = (constraints.min, constraints.max) {
                U8::rand(self, data);
                return
            }
        } 
        
        let mut rng = thread_rng();
        if let Some(strategy) = STRATEGIES.choose(&mut rng) {
            strategy(self, data);
        }
    }
}

struct U16 {
    name: String,
    offset: usize,
    constraints: Option<FieldConstraint>,

}

impl U16 {
    fn new(name: String, offset: usize, constraints: Option<FieldConstraint>) -> Self {
        Self {
            name,
            offset,
            constraints
        }
    }

    fn add(&self, data: &mut [u8]) {
        let value = u16::from_le_bytes(data[self.offset..self.offset + 2].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_add(delta);

        data[self.offset..self.offset + 2].copy_from_slice(&value.to_le_bytes());

    }

    fn sub(&self, data: &mut [u8]) {
        let value = u16::from_le_bytes(data[self.offset..self.offset + 2].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_sub(delta);

        data[self.offset..self.offset + 2].copy_from_slice(&value.to_le_bytes());

    }

    fn rand(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let value = if let Some(constraints) = self.constraints.as_ref() {
            match (constraints.min, constraints.max) {
                (None, None) => {
                    rng.gen::<u16>()
                }
                (Some(min), None) => {
                    rng.gen_range(min as u16..u16::MAX)
                }
                (None, Some(max)) => {
                    rng.gen_range(u16::MIN..max as u16)
                }
                (Some(min), Some(max)) => {
                    rng.gen_range(min..max) as u16
                }
            }
        } else {
            rng.gen()
        };
 
        let bytes = u16::to_le_bytes(value);
        data[self.offset..self.offset + 2].clone_from_slice(&bytes);
    }

    fn magic(&self, data: &mut [u8]) {
        let magic_values = [
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
        ];
        let mut rng = thread_rng();
        if let Some(magic) = magic_values.choose(&mut rng) {
            data[self.offset..self.offset + 2].clone_from_slice(*magic);
        }
    }
}

impl Field for U16 {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        2
    }

    fn mutate(&self, data: &mut [u8]) {
        if data.get(self.offset..self.offset + 2).is_none() {
            return
        }

        const STRATEGIES: &[fn(&U16, &mut [u8])] = &[
            U16::add,
            U16::sub,
            U16::rand,
            U16::magic,
        ];

        if let Some(constraints) = self.constraints.as_ref() {
            if let Some(value) = constraints.value {
                let bytes = u16::to_le_bytes(value as u16);
                data[self.offset..self.offset + 2].clone_from_slice(&bytes);
                return
            }

            if let (Some(_min), Some(_max)) = (constraints.min, constraints.max) {
                U16::rand(self, data);
                return
            }
        } 
        
        let mut rng = thread_rng();
        if let Some(strategy) = STRATEGIES.choose(&mut rng) {
            strategy(self, data);
        }
        
    }

}

struct U32 {
    name: String,
    offset: usize,
    constraints: Option<FieldConstraint>,

}

impl U32 {
    fn new(name: String, offset: usize, constraints: Option<FieldConstraint>) -> Self {
        Self {
            name,
            offset,
            constraints
        }
    }

    fn add(&self, data: &mut [u8]) {
        let value = u32::from_le_bytes(data[self.offset..self.offset + 4].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_add(delta);

        data[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());

    }

    fn sub(&self, data: &mut [u8]) {
        let value = u32::from_le_bytes(data[self.offset..self.offset + 4].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_sub(delta);

        data[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());

    }

    fn rand(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let value = if let Some(constraints) = self.constraints.as_ref() {
            match (constraints.min, constraints.max) {
                (None, None) => {
                    rng.gen::<u32>()
                }
                (Some(min), None) => {
                    rng.gen_range(min as u32..u32::MAX)
                }
                (None, Some(max)) => {
                    rng.gen_range(u32::MIN..max as u32)
                }
                (Some(min), Some(max)) => {
                    rng.gen_range(min..max) as u32
                }
            }
        } else {
            rng.gen()
        };
 
        let bytes = u32::to_le_bytes(value);
        data[self.offset..self.offset + 4].clone_from_slice(&bytes);
    }

    fn magic(&self, data: &mut [u8]) {
        let magic_values = [
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
        ];
        let mut rng = thread_rng();
        if let Some(magic) = magic_values.choose(&mut rng) {
            data[self.offset..self.offset + 4].clone_from_slice(*magic);
        }
    }
}

impl Field for U32 {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        4
    }

    fn mutate(&self, data: &mut [u8]) {
        if data.get(self.offset..self.offset + 4).is_none() {
            return
        }

        const STRATEGIES: &[fn(&U32, &mut [u8])] = &[
            U32::add,
            U32::sub,
            U32::rand,
            U32::magic,
        ];

        if let Some(constraints) = self.constraints.as_ref() {
            if let Some(value) = constraints.value {
                let bytes = u32::to_le_bytes(value as u32);
                data[self.offset..self.offset + 4].clone_from_slice(&bytes);
                return
            }

            if let (Some(_min), Some(_max)) = (constraints.min, constraints.max) {
                U32::rand(self, data);
                return
            }
        } 
        
        let mut rng = thread_rng();
        if let Some(strategy) = STRATEGIES.choose(&mut rng) {
            strategy(self, data);
        }
        
    }

}

struct U64  {
    name: String,
    offset: usize,
    constraints: Option<FieldConstraint>,
}

impl U64 {
    fn new(name: String, offset: usize, constraints: Option<FieldConstraint>) -> Self {
        Self {
            name,
            offset,
            constraints
        }
    }

    fn add(&self, data: &mut [u8]) {
        let value = u64::from_le_bytes(data[self.offset..self.offset + 8].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_add(delta);

        data[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());

    }

    fn sub(&self, data: &mut [u8]) {
        let value = u64::from_le_bytes(data[self.offset..self.offset + 8].try_into().unwrap());

        let range = 16;

        let mut rng = thread_rng();
        let delta = rng.gen_range(0..range);

        let value = value.wrapping_sub(delta);

        data[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());

    }

    fn rand(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let value = if let Some(constraints) = self.constraints.as_ref() {
            match (constraints.min, constraints.max) {
                (None, None) => {
                    rng.gen::<u64>()
                }
                (Some(min), None) => {
                    rng.gen_range(min as u64..u64::MAX)
                }
                (None, Some(max)) => {
                    rng.gen_range(u64::MIN..max as u64)
                }
                (Some(min), Some(max)) => {
                    rng.gen_range(min..max) as u64
                }
            }
        } else {
            rng.gen()
        };
 
        let bytes = u64::to_le_bytes(value);
        data[self.offset..self.offset + 8].clone_from_slice(&bytes);
    }

    fn magic(&self, data: &mut [u8]) {
        let magic_values = [
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
        let mut rng = thread_rng();
        if let Some(magic) = magic_values.choose(&mut rng) {
            data[self.offset..self.offset + 8].clone_from_slice(*magic);
        }
    }
}

impl Field for U64 {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        8
    }

    fn mutate(&self, data: &mut [u8]) {
        if data.get(self.offset..self.offset + 8).is_none() {
            return
        }

        const STRATEGIES: &[fn(&U64, &mut [u8])] = &[
            U64::add,
            U64::sub,
            U64::rand,
            U64::magic,
        ];

        if let Some(constraints) = self.constraints.as_ref() {
            if let Some(value) = constraints.value {
                let bytes = u64::to_le_bytes(value as u64);
                data[self.offset..self.offset + 8].clone_from_slice(&bytes);
                return
            }

            if let (Some(_min), Some(_max)) = (constraints.min, constraints.max) {
                U64::rand(self, data);
                return
            }
        } 
        
        let mut rng = thread_rng();
        if let Some(strategy) = STRATEGIES.choose(&mut rng) {
            strategy(self, data);
        }
 
    }

}

struct WStr {
    name: String,
    offset: usize,
    size: usize,

}

impl WStr {
    fn new(name: String, offset: usize, size: usize) -> Self {
        Self {
            name,
            offset,
            size,
        }
    }
}

impl Field for WStr {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        2 * (self.size + 1)
    }

    // FIXME: read orig as wstr
    // mutate some char
    // write mutated
    // same as u64, need several strategies
    fn mutate(&self, data: &mut [u8]) {
        // if data.get(self.offset..self.offset + 8).is_none() {
            // return
        // }

        // let bytes = u64::to_le_bytes(self.value);
        // data[self.offset..self.offset+8].clone_from_slice(&bytes);

        // let start = self.value as usize;

        if data.get(self.offset).is_none() {
            return
        }

        let end = self.offset as usize + 2 * (self.size + 1);

        if data.get(end).is_none() {
            return
        }

        use rand::distributions::Alphanumeric;
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(self.size)
            .map(char::from)
            .collect();

        let text: Vec::<u16> = rand_string.encode_utf16().collect();
        for (o, &b) in text.iter().enumerate() {
            let offset = self.offset as usize + o * 2;
            let bytes = u16::to_le_bytes(b);
            data[offset..offset + 2].clone_from_slice(&bytes);
        }
    }

}
struct Data {
    name: String,
    offset: usize,
    size: usize,
}

impl Data {
    fn new(name: String, offset: usize, size: usize) -> Self {
        Self {
            name,
            offset,
            size,
        }
    }

    fn rand_offset(&self) -> usize {
        let mut rng = thread_rng();
        rng.gen_range(self.offset..self.offset + self.size)
    }


    fn rand(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let value = rng.gen::<u8>();
        let offset = self.rand_offset();

        data[offset] = value;
    }

    fn bit(&self, data: &mut [u8]) {
        let mut rng = thread_rng();
        let offset = self.rand_offset();
        data[offset] ^= 1u8 << rng.gen_range(0..7);
    }

    fn inc_byte(&self, data: &mut [u8]) {
        let offset = self.rand_offset();
        data[offset] = data[offset].wrapping_add(1);
    }

    fn dec_byte(&self, data: &mut [u8]) {
        let offset = self.rand_offset();
        data[offset] = data[offset].wrapping_sub(1);
    }

    fn neg_byte(&self, data: &mut [u8]) {
        let offset = self.rand_offset();
        data[offset] = !data[offset];
    }
}

impl Field for Data {

    fn name(&self) -> &str {
        &self.name
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn size(&self) -> usize {
        self.size
    }

    fn mutate(&self, data: &mut [u8]) {
        if data.get(self.offset..self.offset + self.size).is_none() {
            return
        }

        const STRATEGIES: &[fn(&Data, &mut [u8])] = &[
            Data::rand,
            Data::bit,
            Data::inc_byte,
            Data::dec_byte,
            Data::neg_byte,
        ];

        let mut rng = thread_rng();
        if let Some(strategy) = STRATEGIES.choose(&mut rng) {
            strategy(self, data);
        }
    }

}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Serialize)]
enum FieldType {
    U8,
    U16,
    U32,
    U64,
    WSTR,
    DATA,

}

impl Default for FieldType {

    fn default() -> Self { 
        Self::U8
    }

}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
struct FieldConstraint {
    min: Option<usize>,
    max: Option<usize>,
    value: Option<usize>,
    size: Option<usize>,

}

/// Basic mutator
#[derive(Default)]
pub struct Mutator {
    /// Fields
    pub fields: Vec<Box<dyn Field>>,

}

impl Mutator {

    fn add_field<F: Field + 'static>(&mut self, field: F) {
        self.fields.push(Box::new(field));
    }

    // FIXME: probability to fuzz a field
    // FIXME: how many fields to mutate
    // FIXME: handle fields count == 1
    /// Choose a random number of fields and mutate them 
    pub fn mutate(&mut self, data: &mut [u8]) {
        if self.fields.is_empty() {
            return
        }

        // let mut rng = thread_rng();
        // let number_of_fields = self.fields.len();
        // let fields_to_mutate = if number_of_fields == 1 {
        //     1
        // } else {
        //     rng.gen_range(1..number_of_fields)
        // };
        // let fields = self.fields.choose_multiple(&mut rng, fields_to_mutate);
        let fields = self.fields.iter();
        for f in fields {
            // FIXME: mutation threshold
            f.mutate(data);
        }

    }

    /// Constructor from field description
    pub fn from(value: &[FieldDesc]) -> Result<Self, GenericError> {
        let mut fuzzed = Self::default();
        // FIXME: need to check in field size are correct with regards to the corpus size
        for desc in value.iter() {
            match desc.r#type {
                FieldType::DATA => {
                    if let Some(constraints) = desc.constraints.as_ref() {
                        if let Some(size) = constraints.size {
                            let field = Data::new(desc.name.clone(), desc.offset, size);
                            fuzzed.add_field(field);
                        } else {
                            return Err(GenericError::Generic("missing size in constraints".to_string()))
                        }
                    } else {
                        return Err(GenericError::Generic("missing constraints".to_string()))
                    }
                }
                FieldType::WSTR => {
                    if let Some(constraints) = desc.constraints.as_ref() {
                        if let Some(size) = constraints.size {
                            let field = WStr::new(desc.name.clone(), desc.offset, size);
                            fuzzed.add_field(field);
                        } else {
                            return Err(GenericError::Generic("missing size in constraints".to_string()))
                        }
                    } else {
                        return Err(GenericError::Generic("missing constraints".to_string()))
                    }
                }
                FieldType::U8 => {
                    let field = U8::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U16 => {
                    let field = U16::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U32 => {
                    let field = U32::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U64 => {
                    let field = U64::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
            };
        }
        Ok(fuzzed)
    }
}

/// Describe field mutation
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct FieldDesc {
    /// Name
    pub name: String,
    /// Offset
    pub offset: usize,
    r#type: FieldType,
    constraints: Option<FieldConstraint>,
    ratio: Option<f64>,
}

/// Describe input layout
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct StructDesc {
    /// Input fields
    pub fields: Vec<FieldDesc>,

}

impl StructDesc {

    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_yaml::to_vec(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Load from disk and deserialize
    pub fn load<P>(path: P) -> Result<Self, crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_yaml::from_str(&input_str)?;
        Ok(input)
    }

}

impl TryFrom<Vec<FieldDesc>> for Mutator {
    type Error = GenericError;

    fn try_from(value: Vec<FieldDesc>) -> Result<Self, Self::Error> {
        let mut fuzzed = Self::default();
        for desc in value.iter() {
            match desc.r#type {
                FieldType::DATA => {
                    if let Some(constraints) = desc.constraints.as_ref() {
                        if let Some(size) = constraints.size {
                            let field = Data::new(desc.name.clone(), desc.offset, size);
                            fuzzed.add_field(field);
                        } else {
                            return Err(GenericError::Generic("missing size in constraints".to_string()))
                        }
                    } else {
                        return Err(GenericError::Generic("missing constraints".to_string()))
                    }
                }
                FieldType::WSTR => {
                    if let Some(constraints) = desc.constraints.as_ref() {
                        if let Some(size) = constraints.size {
                            let field = WStr::new(desc.name.clone(), desc.offset, size);
                            fuzzed.add_field(field);
                        } else {
                            return Err(GenericError::Generic("missing size in constraints".to_string()))
                        }
                    } else {
                        return Err(GenericError::Generic("missing constraints".to_string()))
                    }
                }
                FieldType::U8 => {
                    let field = U8::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U16 => {
                    let field = U16::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U32 => {
                    let field = U32::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
                FieldType::U64 => {
                    let field = U64::new(desc.name.clone(), desc.offset, desc.constraints.clone());
                    fuzzed.add_field(field);
                }
            };
        }
        Ok(fuzzed)
    }
}

/// Description of input
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct InputItemDesc {
    /// Name
    pub name: String,
    /// Address
    pub address: u64,
    /// Offset in file
    pub offset: usize,
    /// Size
    pub size: usize,
    /// Fields
    pub fields: Vec<FieldDesc>,
}

/// Describe input layout
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct InputDesc {
    /// List of inputs
    pub items: Vec<InputItemDesc>,
}

impl InputDesc {

    /// Serialize to yaml and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_yaml::to_vec(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Load from disk and deserialize from yaml
    pub fn load<P>(path: P) -> Result<Self, crate::error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_yaml::from_str(&input_str)?;
        Ok(input)
    }

}


#[cfg(test)]
mod test {
    use crate::mutation::*;

    fn compute_checksum(data: &[u8]) -> u16 {
        data.iter().fold(0, |acc, e| {
            acc.wrapping_add((*e).into())
        })
    }

    #[test]
    fn test_parse_yaml() {
        let path = "tests/fixtures/test.yaml";
        let desc = StructDesc::load(path).unwrap();
        dbg!(&desc);
        assert_eq!(desc.fields.len(), 12);

        assert_eq!(desc.fields[0].name, "magic");
    }

    #[test]
    fn test_from_yaml() {
        let path = "tests/fixtures/test.yaml";
        let desc = StructDesc::load(path).unwrap();

        let mut buffer = vec![0u8; 0x100];

        let mut fuzzed: Mutator = desc.fields.try_into().unwrap();
        fuzzed.mutate(&mut buffer);

        use pretty_hex::*;

        println!("{:?}", buffer.hex_dump());

        fuzzed.mutate(&mut buffer);

        println!("{:?}", buffer.hex_dump());

    }

    #[test]
    fn test_mutate_u8() {
        let mut buffer = vec![0u8; 0x10];

        let f = U8::new("test".to_string(), 4, None);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = U8::new("test".to_string(), 0x20, None);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_mutate_u16() {
        let mut buffer = vec![0u8; 0x10];

        let f = U16::new("test".to_string(), 4, None);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = U16::new("test".to_string(), 0x20, None);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_mutate_u32() {
        let mut buffer = vec![0u8; 0x10];

        let f = U32::new("test".to_string(), 4, None);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = U32::new("test".to_string(), 0x20, None);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_mutate_u64() {
        let mut buffer = vec![0u8; 0x10];

        let f = U64::new("test".to_string(), 4, None);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = U64::new("test".to_string(), 0x20, None);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_mutate_wstr() {
        let mut buffer = vec![0u8; 0x10];

        let f = WStr::new("test".to_string(), 4, 4);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = WStr::new("test".to_string(), 0x20, 4);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_mutate_data() {
        let mut buffer = vec![0u8; 0x10];

        let f = Data::new("test".to_string(), 4, 8);

        for _ in 0..0x100 {
            f.mutate(&mut buffer);
        }

        let f = Data::new("test".to_string(), 0x20, 8);

        for _ in 0..0x100 {
            let checksum = compute_checksum(&buffer);
            f.mutate(&mut buffer);
            assert_eq!(checksum, compute_checksum(&buffer));
        }
    }

    #[test]
    fn test_parse_yaml2() {
        let path = "tests/fixtures/test2.yaml";
        let desc = StructDesc::load(path).unwrap();
        dbg!(&desc);
        assert_eq!(desc.fields.len(), 1);

        assert_eq!(desc.fields[0].name, "data");
    }

    #[test]
    fn test_build_yaml() {
        let mut desc = StructDesc::default();
        let field = FieldDesc::default();
        desc.fields.push(field);

        let path = "tests/fixtures/generated.yaml";
        desc.save(path).unwrap();

        assert_eq!(desc.fields.len(), 1);
    }

}

