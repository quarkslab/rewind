
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use std::sync::{Arc, RwLock};

use crate::error;

#[derive(Debug)]
pub struct Entry {
    pub hash: u64,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct Corpus {
    pub workdir: std::path::PathBuf,
    pub members: HashMap<u64, Entry>,
    index: Arc<RwLock<usize>>,
}

impl Corpus {
    pub fn new<S>(workdir: S) -> Self 
    where S: Into<std::path::PathBuf> {
        // FIXME: check if corpus and crashes directories are created
        Corpus {
            workdir: workdir.into(),
            members: HashMap::new(),
            index: Default::default(),
       }
    }

    pub fn load(&mut self) -> Result<usize, error::GenericError> {
        let path = Path::new(&self.workdir).join("corpus");
        let paths = fs::read_dir(path)?;
        let mut total = 0;
        for path in paths {
            let path = path?.path();
            if path.extension() == Some(OsStr::new("bin")) {
                let mut file = File::open(&path)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let hash = calculate_hash(&data);
                let entry = Entry {
                    hash,
                    data,
                };
                self.members.insert(hash, entry);
                total += 1;
            }
        }

        Ok(total)
    }

    pub fn add(&mut self, input: Vec<u8>) -> Result<(), error::GenericError> {
        let hash = calculate_hash(&input);
        let entry = Entry {
            hash,
            data: input,
        };
        self.members.insert(hash, entry);
        Ok(())
    }

    pub fn remove(&mut self, path: PathBuf) -> Result<(), error::GenericError> {
        if path.extension() != Some(OsStr::new("bin")) {
            return Err(error::GenericError::Generic("bad extension".into()))
        }

        if let Some(filename) = path.file_stem() {
            let file = filename.to_str().ok_or_else(|| error::GenericError::Generic("bad filename".into()))?;
            let hash = u64::from_str_radix(file, 16).map_err(|_| error::GenericError::Generic("can't parse filename".into()))?;
            self.members.remove(&hash);
        }
        Ok(())
    }

    pub fn rotate(&mut self) -> Option<(&u64, &Entry)> {
        if self.members.is_empty() {
            return None
        }
        let item = self.index.try_write();
        let item = if let Ok(mut index) = item {
            *index = (*index + 1) % self.members.len();

            self.members.iter().nth(*index)
        } else { None };
        item
    }
}

pub fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}
