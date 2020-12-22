
use std::convert::TryInto;
use std::time::Duration;
use std::str::FromStr;

use std::io::{BufWriter, Write};

use std::thread;
use std::sync::mpsc;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use serde::{Serialize, Deserialize};

use chrono::{Utc, DateTime};

use anyhow::Result;

// use ni_rs;

use crate::trace;
use crate::watch;

use crate::helpers::convert;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Stats {
    pub iterations: u64,
    // pub total_iterations: u64,
    pub coverage: u64,
    // pub total_coverage: u64,
    pub code: usize,
    pub data: usize,
    pub start: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    // pub total_start: Instant,
    // interval: Duration,
    pub corpus_size: usize,
    pub worklist_size: usize,
    pub crashes: u64,
    pub uuid: uuid::Uuid,
}

impl Stats {
    pub fn new() -> Self {
        let start = Utc::now();
        let uuid = uuid::Uuid::new_v4();
        Stats {
            iterations: 0,
            // total_iterations: 0,
            coverage: 0,
            // total_coverage: 0,
            code: 0,
            data: 0,
            start: start,
            updated: start,
            // total_start: start,
            // interval: interval,
            corpus_size: 0,
            worklist_size: 0,
            crashes: 0,
            uuid,
        }
    }

    // pub fn reset(&mut self) {
    //     self.iterations = 0;
    //     self.coverage = 0;
    //     self.start = Instant::now()
    // }

    // pub fn update_display(&mut self) -> Option<String> {
    //     if self.start.elapsed() > self.interval {
    //         Some(self.display())
    //     } else {
    //         None
    //     }
    // }

    pub fn display(&mut self) -> String {
        let elapsed = self.updated - self.start;
        let msg = format!("{} executions, {} exec/s, coverage {}, code {}, data {}, corpus {}, worklist {}, crashes {}",
            self.iterations,
            self.iterations / elapsed.num_seconds() as u64,
            self.coverage,
            convert((self.code * 0x1000) as f64),
            convert((self.data * 0x1000) as f64),
            self.corpus_size,
            self.worklist_size,
            self.crashes);
        msg
    }

    pub fn elapsed(&self) -> Duration {
        let elapsed = Utc::now() - self.start;
        elapsed.to_std().unwrap()
    }

    pub fn last_updated(&self) -> Duration {
        let elapsed = Utc::now() - self.updated;
        elapsed.to_std().unwrap()
    }

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path> {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl From<&Params> for trace::Input {

    fn from(params: &Params) -> Self {
        Self {
            address: params.input.into(),
            size: params.input.into(),
        }
    }
}


#[derive(Default, Serialize, Deserialize)]
pub struct Params {
    pub snapshot_path: std::path::PathBuf,
    pub max_iterations: u64,
    pub max_duration: Duration,
    pub input: u64,
    pub input_size: u64,
    pub stop_on_crash: bool,
    pub display_delay: Duration,
}


impl Params {

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: Into<std::path::PathBuf> {
        let path = path.into();
        let mut fp = BufWriter::new(std::fs::File::create(path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Params {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let input = serde_json::from_str(s)?;
        Ok(input)
    }
}


pub struct Corpus {
    pub workdir: std::path::PathBuf,
    pub members: HashMap<u64, Vec<u8>>,
}

impl Corpus {
    pub fn new<S>(workdir: S) -> Self 
    where S: Into<std::path::PathBuf> {
        // FIXME: check if corpus and crashes directories are created
        Corpus {
            workdir: workdir.into(),
            members: HashMap::new()
       }
    }

    pub fn load(&mut self) -> Result<usize> {
        let path = Path::new(&self.workdir).join("corpus");
        let paths = fs::read_dir(path)?;
        let mut total = 0;
        for path in paths {
            let path = path?.path();
            if path.extension() == Some(OsStr::new("bin")) {
                let mut file = File::open(&path)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                // fs::remove_file(path)?;
                let hash = calculate_hash(&data);
                self.members.insert(hash, data);
                total += 1;
            }
        }

        Ok(total)
    }

    pub fn add(&mut self, input: &Vec<u8>) -> Result<()> {
        // self.queue.insert(coverage, input.to_vec());
        let hash = calculate_hash(input);
        match self.members.insert(hash, input.to_vec()) {
            None => {
                info!("file was added to corpus");
            }
            _ => ()
        }
        // let path = Path::new(&self.workdir)
            // .join("corpus")
            // .join(format!("{:x}.bin", hash));
        // let mut file = File::create(path)?;
        // file.write_all(&input)?;
        Ok(())
    }

}

pub fn calculate_hash<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

// FIXME: need a Mutator trait
// with just mutate input
// should return a ref
// should work inplace

pub trait Strategy {

    // fn mutate_input(&mut self, input: &[u8]) -> Vec<u8>;

    fn select_input(&mut self, corpus: &mut Corpus) -> Option<Vec<u8>>;

    fn load_corpus(&mut self) -> anyhow::Result<()>;

    fn handle_new_corpus(&mut self, data: &[u8]) -> anyhow::Result<()>;

    fn handle_stats(&mut self, path: &Path, stats: &mut Stats) -> anyhow::Result<()>;

    fn handle_execution(&mut self, params: &Params, data: &[u8], trace: &mut trace::Trace, corpus: &mut Corpus) -> anyhow::Result<usize>;

    fn get_coverage(&mut self) -> usize;

    fn get_queue_size(&mut self) -> usize;

}

// impl Strategy for Box<dyn Strategy> {

//     fn select_input(&mut self, corpus: &mut Corpus) -> Option<Vec<u8>> {
//         self.as_mut().select_input(corpus)
//     }

//     fn handle_stats(&mut self) -> {

//     }
//     fn handle_execution(&mut self, params: &Params, data: &[u8], trace: &mut trace::Trace, corpus: &mut Corpus) -> anyhow::Result<usize> {
//         self.as_mut().handle_execution(params, data, trace, corpus)
//     }

//     fn get_coverage(&mut self) -> usize {
//         self.as_mut().get_coverage()
//     }

//     fn get_queue_size(&mut self) -> usize {
//         self.as_mut().get_queue_size()
//     }

// }

// FIXME: need to pass that as parameter
#[derive(Default)]
pub struct Hook {

}

impl trace::Hook for Hook {

    fn setup<T: trace::Tracer>(&self, _tracer: &mut T) {

    }

    fn handle_breakpoint<T: trace::Tracer>(&mut self, _tracer: &mut T) -> Result<bool> {
        Ok(true)
    }

    fn handle_trace(&self, _trace: &mut trace::Trace) -> Result<bool> {
        Ok(true)
    }
}

pub struct Fuzzer {
    path: std::path::PathBuf,
    channel: mpsc::Receiver<Vec<u8>>,
}

impl Fuzzer {
    pub fn new<S>(path: S) -> Result<Self>
    where S: Into<std::path::PathBuf> {
        let (tx, rx) = mpsc::channel();

        let path = path.into();
        let fuzzer = Fuzzer {
            path: path,
            channel: rx,
        };

        let sender = tx.clone();
        let copy = fuzzer.path.join("corpus").clone();
        let _thread = thread::spawn(move || {
            loop {
                let result = watch::watch(&sender, &copy);
                println!("{:?}", result);
            }
        });

        Ok(fuzzer)
    }

    pub fn run<T, S>(&mut self, strategy: &mut S, params: &Params, tracer: &mut T, context: &trace::ProcessorState, trace_params: &trace::Params) -> Result<Stats> 
    where
        T: trace::Tracer,
        S: Strategy,
     {
        info!("running fuzzer");
        let mut stats = Stats::new();

        info!("first execution to map memory");

        tracer.set_state(&context)?;
        // FIXME: as parameters
        let mut hook = Hook {};
        let mut trace = tracer.run(trace_params, &mut hook)?;
        match trace.status {
            trace::EmulationStatus::Success => {
            }
            _ => {
                return Err(anyhow!("first execution failed!"))
            }
        }

        tracer.restore_snapshot()?;

        info!("reading input");
        let input_size: usize = params.input_size.try_into()?;
        if input_size == 0 {
            return Err(anyhow!("input size can't be 0"))
        }

        let mut data = vec![0u8; input_size];

        let cr3 = tracer.cr3()?;
        tracer.read_gva(cr3, params.input, &mut data)?;

        let mut corpus = Corpus::new(&self.path);
        info!("add first trace to corpus");

        // FIXME: strategy.load_corpus (send tracer + corpus)
        strategy.load_corpus()?;
        let _new = strategy.handle_execution(&params, &data, &mut trace, &mut corpus)?;

        stats.iterations += 1;

        stats.coverage = strategy.get_coverage() as u64;

        stats.code += trace.code;
        stats.data += trace.data;

        let files = corpus.load()?;
        info!("loaded {} file(s) from corpus", files);

        info!("start fuzzing");

        loop {
            strategy.handle_stats(self.path.as_path(), &mut stats)?;

            // FIXME: reload corpus periodically ?
            match self.channel.try_recv() {
                Ok(data) => {
                    // FIXME: strategy new corpus
                    strategy.handle_new_corpus(&data)?;
                    corpus.add(&data)?;
                }
                _ => {}
            }

            let input = match strategy.select_input(&mut corpus) {
                None => {
                    error!("no more input, stop");
                    return Err(anyhow!("no more input"));
                }
                Some(data) => data,
            };

            // println!("{:x?}", &input[..0x30]);
            // input.resize(input_size, 0);
            // let mutated = strategy.mutate_input(&input[..]);
            // data[..].copy_from_slice(&mutated);
            // FIXME: handle input size
            match tracer.write_gva(cr3, params.input, &input[..0x1000]) {
                Ok(()) => {}
                Err(e) => {
                    error!("can't write fuzzer input {:?}", e);
                    return Err(anyhow!("can't write fuzzer input"));
                }
            }

            tracer.set_state(&context)?;

            let mut trace = tracer.run(trace_params, &mut hook)?;

            tracer.restore_snapshot()?;

            let _new = strategy.handle_execution(&params, &input, &mut trace, &mut corpus)?;

            // FIXME: need to address error too
            match trace.status {
                trace::EmulationStatus::ForbiddenAddress(_) => {
                    stats.crashes += 1;
                    if params.stop_on_crash {
                        break;
                    }
                }
                trace::EmulationStatus::Success => {},
                _ => {
                    warn!("got {:?}", trace.status);
                }
            }

            stats.iterations += 1;

            stats.coverage = strategy.get_coverage() as u64;

            // FIXME: tracer.get_mem
            stats.code += trace.code;
            stats.data += trace.data;

            stats.corpus_size = corpus.members.len();
            stats.worklist_size = strategy.get_queue_size();
            
            // FIXME: strategy handle_stats?
            if params.max_duration.as_secs() != 0 && stats.elapsed() > params.max_duration {
                break;
            }

            if params.max_iterations != 0 && stats.iterations > params.max_iterations {
                break;
            }

        }

        strategy.handle_stats(self.path.as_path(), &mut stats)?;

        Ok(stats)
    }
}

#[derive(Serialize, Deserialize)]
pub struct MutationHint {
    pub immediates: BTreeSet<u64>,
    pub offsets: BTreeSet<u64>
}

impl MutationHint {

    pub fn new() -> Self {
        Self {
            immediates: BTreeSet::new(),
            offsets: BTreeSet::new()
        }
    }

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}