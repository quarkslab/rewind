
//! Fuzzer implementation

use std::path::PathBuf;
use std::time::Duration;
use std::str::FromStr;

use std::io::{BufWriter, Write};

use std::thread;
use std::sync::mpsc;

use serde::{Serialize, Deserialize};

use chrono::{Utc, DateTime};

use thiserror::Error;

use crate::mutation::{InputItemDesc, Mutator};
use crate::trace::EmulationStatus;
use crate::{mutation::MutationHint, trace};
use crate::watch;
use crate::error::{self, GenericError};
use crate::corpus::{calculate_hash, Corpus};

use crate::helpers::convert;

/// Fuzzing statistics
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Stats {
    /// Number of test cases executed
    pub iterations: u64,
    /// Global coverage (counting all corpus entries)
    pub coverage: u64,
    /// Number of pages mapped by on-demand paging
    pub mapped_pages: usize,
    /// Session start
    pub start: DateTime<Utc>,
    /// Session updated
    pub updated: DateTime<Utc>,
    /// Corpus entries
    pub corpus_size: usize,
    /// Number of crashes
    pub crashes: u64,
    /// Fuzzer session identifier
    pub uuid: uuid::Uuid,
    /// If fuzzing session was terminated
    pub done: bool,
}

impl Stats {
    /// Construct a fuzzing session statistics
    pub fn new() -> Self {
        let start = Utc::now();
        let uuid = uuid::Uuid::new_v4();
        Stats {
            iterations: 0,
            coverage: 0,
            mapped_pages: 0,
            start,
            updated: start,
            corpus_size: 0,
            crashes: 0,
            uuid,
            done: false
        }
    }

    /// Time since fuzzing start
    pub fn elapsed(&self) -> Duration {
        let elapsed = Utc::now() - self.start;
        elapsed.to_std().unwrap()
    }

    /// Time since stats were updated
    pub fn last_updated(&self) -> Duration {
        let elapsed = Utc::now() - self.updated;
        elapsed.to_std().unwrap()
    }

    /// Serialize and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path> {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Load from disk and deserialize
    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Stats {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elapsed = Utc::now() - self.start;
        let num_seconds = std::cmp::max(1, elapsed.num_seconds());
        write!(f, "{} executions, {} exec/s, coverage {}, mapped pages {}, corpus {}, crashes {}",
            self.iterations,
            self.iterations / num_seconds as u64,
            self.coverage,
            convert((self.mapped_pages * 0x1000) as f64),
            self.corpus_size,
            self.crashes)
    }
}

impl From<&Params> for trace::Input {

    fn from(params: &Params) -> Self {
        Self {
            address: params.input,
            size: params.input_size,
        }
    }
}

/// Fuzzing parameters
#[derive(Default, Serialize, Deserialize)]
pub struct Params {
    /// Path to snapshot
    pub snapshot_path: std::path::PathBuf,
    /// Max number of iterations, 0 means infinite
    pub max_iterations: u64,
    /// Max duration
    pub max_duration: Duration,
    /// Address of fuzzed input 
    pub input: u64,
    /// Size of fuzzed input
    pub input_size: u64,
    /// If true, stop upon first crash
    pub stop_on_crash: bool,
    // pub display_delay: Duration,
}


impl Params {

    /// Serialize and save parameters to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: Into<std::path::PathBuf> {
        let path = path.into();
        let mut fp = BufWriter::new(std::fs::File::create(path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Deserialize and load parameters from disk
    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Params {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = serde_json::from_str(s)?;
        Ok(input)
    }
}


// FIXME: need a Mutator trait
// with just mutate input
// should return a ref
// should work inplace
// FIXME: add associated error type 

/// Fuzzing strategy
pub trait Strategy {

    /// Generate a new input
    fn generate_new_input(&mut self, data: &mut [u8], corpus: &mut Corpus, hint: &mut MutationHint);

    /// Check if input has increased coverage
    fn check_new_coverage(&mut self, params: &Params, trace: &mut trace::Trace) -> usize; 

    /// Get coverage
    fn get_coverage(&mut self) -> usize;

}


/// Fuzzing strategy
pub trait Strategy2 {

    /// Replay corpus
    fn replay_corpus<T: trace::Tracer, H: trace::Hook>(&mut self, tracer: &mut T, hook: &mut H, context: &trace::ProcessorState, corpus: &mut Corpus) -> Result<(), FuzzerError>;

    /// Execute testcase
    fn execute<T: trace::Tracer, H: trace::Hook>(&mut self, tracer: &mut T, hook: &mut H, context: &trace::ProcessorState, corpus: &mut Corpus, first: bool) -> Result<(), FuzzerError>;

    /// Get coverage
    fn get_coverage(&mut self) -> usize;

}

/// Fair strategy
pub struct FairStrategy <'a> {
    inputs: std::collections::BTreeMap<u64, (InputItemDesc, Mutator)>,
    trace: trace::Trace,
    trace_params: &'a trace::Params,
    buffer: Vec<u8>,
    current_mutation: usize,
    number_of_mutations: usize,
    fuzzer_workdir: PathBuf,
}

impl <'a> FairStrategy <'a> {

    /// Constructor
    pub fn new(fuzzer_workdir: PathBuf, input_desc: crate::mutation::InputDesc, params: &'a trace::Params) -> Result<Self, GenericError> {
        let mut inputs = std::collections::BTreeMap::new();

        let mut corpus_size = 0;
        for item in input_desc.items { 
            let mutator = crate::mutation::Mutator::from(&item.fields)?;
            corpus_size += item.size;
            inputs.insert(item.address, (item, mutator));
        }

        // FIXME: should be in yaml
        let number_of_mutations = 1024;
        let buffer = vec![0u8; corpus_size];

        let trace = trace::Trace::default();

        Ok(Self {
            inputs,
            trace,
            trace_params: params,
            buffer,
            number_of_mutations,
            current_mutation: 0,
            fuzzer_workdir,
        })
    }

    // fn check_coverage(&self) {
    //     // FIXME: should be in strategy
    //     if new > 0 {
    //         // save corpus
    //         let hash = calculate_hash(&data);
    //         let path = std::path::Path::new(&self.path)
    //             .join("corpus")
    //             .join(format!("{:x}.bin", hash));
    //         println!("discovered {} new address(es), adding file {:?} to corpus", new, path);
    //         let mut file = std::fs::File::create(path)?;
    //         file.write_all(&data)?;

    //         match trace.status {
    //             trace::EmulationStatus::Success => {},
    //             _ => {
    //                 let hash = calculate_hash(&data);
    //                 let path = std::path::Path::new(&self.path)
    //                     .join("crashes")
    //                     .join(format!("{:x}.bin", hash));
    //                 println!("got abnormal exit {}, saving input to {:?}", trace.status, path);
    //                 let mut file = std::fs::File::create(path)?;
    //                 file.write_all(&data)?;

    //                 stats.crashes += 1;
    //                 if params.stop_on_crash {
    //                     break;
    //                 }
    //             }
    //         }
    //     }
    // }
}


impl <'a> Strategy2 for FairStrategy <'a> {

    fn replay_corpus<T: trace::Tracer, H: trace::Hook>(&mut self, tracer: &mut T, hook: &mut H, context: &trace::ProcessorState, corpus: &mut Corpus) -> Result<(), FuzzerError> {
        let cr3 = tracer.cr3()?;

        for (_hash, entry) in corpus.members.iter_mut() {
            if entry.data.len() < self.buffer.len() {
                let msg = format!("corpus file is too small, need at least 0x{:x} bytes, got 0x{:x}",
                    self.buffer.len(),
                    entry.data.len());
                return Err(FuzzerError::CorpusError(msg))
            }
            tracer.set_state(context)?;
            for (_address, (input, _mutator)) in self.inputs.iter() {
                let data = &entry.data[input.offset..input.offset + input.size];
                trace::Tracer::write_gva(tracer, cr3, input.address, data)?;
            }
            tracer.run_with_trace(self.trace_params, hook, &mut self.trace)?;
            tracer.restore_snapshot()?;
        }

        Ok(())
    }

    fn execute<T: trace::Tracer, H: trace::Hook>(&mut self, tracer: &mut T, hook: &mut H, context: &trace::ProcessorState, corpus: &mut Corpus, first: bool) -> Result<(), FuzzerError> {
        // select input
        // mutate input
        // write input
        // execute input

        tracer.set_state(context)?;
        if first {
            let cr3 = tracer.cr3()?;
            tracer.run_with_trace(self.trace_params, hook, &mut self.trace)?;
            if self.trace.status != trace::EmulationStatus::Success  {
                return Err(FuzzerError::FirstExecFailed("first execution failed!".to_string()))
            }
            tracer.restore_snapshot()?;

            for (_address, (input, _mutator)) in self.inputs.iter() {
                let data = &mut self.buffer[input.offset..input.offset + input.size];
                trace::Tracer::read_gva(tracer, cr3, input.address, data)?;
            }

            let hash = calculate_hash(&self.buffer);
            let path = std::path::Path::new(&self.fuzzer_workdir)
                .join("corpus")
                .join(format!("{:x}.bin", hash));
            let mut file = std::fs::File::create(path)?;
            file.write_all(&self.buffer)?;

            // corpus.add(self.buffer.clone())?;

        } else {
            if self.current_mutation >= self.number_of_mutations {
                self.current_mutation = 0;
                if let Some((_hash, entry)) = corpus.rotate() {
                    let length = self.buffer.len();
                    self.buffer[..].copy_from_slice(&entry.data[..length]);
                }
            } else {
                self.current_mutation += 1;
            }
            let cr3 = tracer.cr3()?;
            for (_address, (input, mutator)) in self.inputs.iter_mut() {
                // need to create one buffer for all inputs
                // since it will saved as corpus file
                let data = &mut self.buffer[input.offset..input.offset + input.size];
                mutator.mutate(data);
                trace::Tracer::write_gva(tracer, cr3, input.address, data)?;
            }
            
            let previous_coverage = self.get_coverage();

            // let mut trace = tracer.run(self.trace_params, hook)?;
            // let new = self.trace.seen.difference(&trace.seen).count();
            // self.trace.seen.append(&mut trace.seen);
        
            tracer.run_with_trace(self.trace_params, hook, &mut self.trace)?;
            tracer.restore_snapshot()?;

            let new_coverage = self.get_coverage();

            if new_coverage > previous_coverage {
                let new = new_coverage - previous_coverage;
                let hash = calculate_hash(&self.buffer);
                let path = std::path::Path::new(&self.fuzzer_workdir)
                    .join("corpus")
                    .join(format!("{:x}.bin", hash));
                println!("discovered {} new address(es), adding file {:?} to corpus", new, path);
                let mut file = std::fs::File::create(path)?;
                file.write_all(&self.buffer)?;
            }

            if self.trace.status != EmulationStatus::Success {
                let hash = calculate_hash(&self.buffer);
                let path = std::path::Path::new(&self.fuzzer_workdir)
                    .join("crashes")
                    .join(format!("{:x}.bin", hash));
                println!("got abnormal exit {}, saving input to {:?}", self.trace.status, path);
                let mut file = std::fs::File::create(path)?;
                file.write_all(&self.buffer)?;

            }

        }

        Ok(())
    }

    fn get_coverage(&mut self) -> usize {
        self.trace.seen.len()
    }
}

/// Fuzzing errors
#[derive(Debug, Error)]
pub enum FuzzerError {
    /// IO error
    #[error(transparent)]
    FileError(#[from]std::io::Error),
    /// Serde error
    #[error(transparent)]
    SerdeError(#[from]serde_json::Error),
    /// Unspecified error
    #[error(transparent)]
    GenericError(#[from]error::GenericError),
    /// Tracer error
    #[error(transparent)]
    TracerError(#[from]trace::TracerError),
    /// Error during dry run
    #[error("first execution failed: {}", .0)]
    FirstExecFailed(String),
    /// Input size error
    #[error("bad input size: 0x{:x}", .0)]
    BadInputSize(usize),
    /// Corpus error
    #[error("{}", .0)]
    CorpusError(String),


}

/// Fuzzer instance
pub struct Fuzzer<'a> {
    path: std::path::PathBuf,
    channel: mpsc::Receiver<watch::Event>,
    callback: Option<Box<dyn FnMut(&Stats) + 'a>>,
}

impl <'a> Fuzzer <'a> {
    /// Construct a new fuzzer instance
    pub fn new<S>(path: S) -> Result<Self, FuzzerError>
    where S: Into<std::path::PathBuf> {
        let (tx, rx) = mpsc::channel();

        let path = path.into();
        let fuzzer = Fuzzer {
            path,
            channel: rx,
            callback: None
        };

        // FIXME: no need to have channel in constructor, just needed in run method
        let sender = tx;
        let copy = fuzzer.path.join("corpus");
        let _thread = thread::spawn(move || {
            loop {
                let result = watch::watch(&sender, &copy);
                println!("{:?}", result);
            }
        });

        Ok(fuzzer)
    }

    /// Register a fuzzing loop callback
    pub fn callback(&mut self, callback: impl FnMut(&Stats) + 'a) {
        self.callback = Some(Box::new(callback));
    }

    /// Run fuzzer
    #[allow(clippy::too_many_arguments)]
    pub fn run<T, S, H>(&mut self, corpus: &mut Corpus, strategy: &mut S, params: &Params, tracer: &mut T, context: &trace::ProcessorState, trace_params: &trace::Params, hook: &mut H) -> Result<Stats, FuzzerError> 
    where
        T: trace::Tracer,
        H: trace::Hook,
        S: Strategy,
     {
        let mut stats = Stats::new();

        // first execution to map memory
        tracer.set_state(context)?;
        let trace = tracer.run(trace_params, hook)?;
        match trace.status {
            trace::EmulationStatus::Success => {
            }
            _ => {
                return Err(FuzzerError::FirstExecFailed("first execution failed!".to_string()))
            }
        }

        tracer.restore_snapshot()?;

        let input_size: usize = params.input_size as usize;
        if input_size == 0 {
            return Err(FuzzerError::BadInputSize(0))
        }

        let mut data = vec![0u8; input_size];

        let cr3 = tracer.cr3()?;
        tracer.read_gva(cr3, params.input, &mut data)?;

        stats.iterations += 1;

        stats.coverage = strategy.get_coverage() as u64;

        stats.mapped_pages = tracer.get_mapped_pages()?;

        corpus.load()?;

        // FIXME: replay corpus members
        for (_hash, entry) in corpus.members.iter_mut() {
            tracer.set_state(context)?;
            let range = std::cmp::min(entry.data.len(), 0x1000);
            tracer.write_gva(cr3, params.input, &entry.data[..range])?;
            let mut trace = tracer.run(trace_params, hook)?;
            strategy.check_new_coverage(params, &mut trace);
            tracer.restore_snapshot()?;
        }

        let mut last_refresh = std::time::Instant::now();
        let mut hint = MutationHint::default();

        loop {
            if let Some(callback) = self.callback.as_mut() {
                callback(&stats);
            }

            if last_refresh.elapsed() > std::time::Duration::from_secs(2) {
                let path = std::path::Path::new(&self.path).join("hints.json");
                if let Ok(mutation_hint) = MutationHint::load(path) {
                    hint = mutation_hint;
                }

                let path = self.path.join("instances").join(format!("{}.json", stats.uuid));
                stats.updated = Utc::now();
                stats.save(path)?;

                last_refresh = std::time::Instant::now()

            }
        
            if let Ok(event)  = self.channel.try_recv() {
                match event {
                    watch::Event::Create { data, .. } => {
                        // FIXME: need a way to separate files produced by us
                        tracer.set_state(context)?;
                        let range = std::cmp::min(data.len(), 0x1000);
                        tracer.write_gva(cr3, params.input, &data[..range])?;
                        let mut trace = tracer.run(trace_params, hook)?;
                        strategy.check_new_coverage(params, &mut trace);
                        tracer.restore_snapshot()?;
                        corpus.add(data)?;
                    }
                    watch::Event::Remove(path) => {
                        corpus.remove(path)?;

                    }
                }
            }

            strategy.generate_new_input(&mut data, corpus, &mut hint);

            let range = std::cmp::min(data.len(), 0x1000);
            tracer.write_gva(cr3, params.input, &data[..range])?;

            tracer.set_state(context)?;

            let mut trace = tracer.run(trace_params, hook)?;

            tracer.restore_snapshot()?;

            let new = strategy.check_new_coverage(params, &mut trace);

            // FIXME: should be in strategy
            if new > 0 {
                // save corpus
                let hash = calculate_hash(&data);
                let path = std::path::Path::new(&self.path)
                    .join("corpus")
                    .join(format!("{:x}.bin", hash));
                println!("discovered {} new address(es), adding file {:?} to corpus", new, path);
                let mut file = std::fs::File::create(path)?;
                file.write_all(&data)?;

                match trace.status {
                    trace::EmulationStatus::Success => {},
                    _ => {
                        let hash = calculate_hash(&data);
                        let path = std::path::Path::new(&self.path)
                            .join("crashes")
                            .join(format!("{:x}.bin", hash));
                        println!("got abnormal exit {}, saving input to {:?}", trace.status, path);
                        let mut file = std::fs::File::create(path)?;
                        file.write_all(&data)?;

                        stats.crashes += 1;
                        if params.stop_on_crash {
                            break;
                        }
                    }
                }
            }

            stats.iterations += 1;

            stats.coverage = strategy.get_coverage() as u64;

            stats.mapped_pages = tracer.get_mapped_pages()?;

            stats.corpus_size = corpus.members.len();
            
            if params.max_duration.as_secs() != 0 && stats.elapsed() > params.max_duration {
                break;
            }

            if params.max_iterations != 0 && stats.iterations > params.max_iterations {
                break;
            }

        }

        stats.done = true;

        if let Some(callback) = self.callback.as_mut() {
            callback(&stats);
        }

        Ok(stats)
    }

    /// Run fuzzer
    #[allow(clippy::too_many_arguments)]
    pub fn run2<T, S, H>(&mut self, corpus: &mut Corpus, strategy: &mut S, params: &Params, tracer: &mut T, context: &trace::ProcessorState, _trace_params: &trace::Params, hook: &mut H) -> Result<Stats, FuzzerError> 
    where
        T: trace::Tracer,
        H: trace::Hook,
        S: Strategy2,
     {
        let mut stats = Stats::new();

        // first execution to map memory
        strategy.execute(tracer, hook, context, corpus, true)?;

        stats.iterations += 1;
        stats.coverage = strategy.get_coverage() as u64;
        stats.mapped_pages = tracer.get_mapped_pages()?;

        corpus.load()?;

        strategy.replay_corpus(tracer, hook, context, corpus)?;

        let mut last_refresh = std::time::Instant::now();
        let mut _hint = MutationHint::default();

        loop {
            if let Some(callback) = self.callback.as_mut() {
                callback(&stats);
            }

            if last_refresh.elapsed() > std::time::Duration::from_secs(2) {
                let path = std::path::Path::new(&self.path).join("hints.json");
                if let Ok(mutation_hint) = MutationHint::load(path) {
                    _hint = mutation_hint;
                }

                let path = self.path.join("instances").join(format!("{}.json", stats.uuid));
                stats.updated = Utc::now();
                stats.save(path)?;

                last_refresh = std::time::Instant::now()

            }
        
            if let Ok(event)  = self.channel.try_recv() {
                match event {
                    watch::Event::Create { data, .. } => {
                        corpus.add(data)?;
                    }
                    watch::Event::Remove(path) => {
                        corpus.remove(path)?;

                    }
                }
            }

            strategy.execute(tracer, hook, context, corpus, false)?;

            stats.iterations += 1;
            stats.coverage = strategy.get_coverage() as u64;
            stats.mapped_pages = tracer.get_mapped_pages()?;
            stats.corpus_size = corpus.members.len();
            
            if params.max_duration.as_secs() != 0 && stats.elapsed() > params.max_duration {
                break;
            }

            if params.max_iterations != 0 && stats.iterations > params.max_iterations {
                break;
            }

        }

        stats.done = true;

        if let Some(callback) = self.callback.as_mut() {
            callback(&stats);
        }

        Ok(stats)
    }
}



#[cfg(test)]
mod test {

    use crate::mutation::*;
    use crate::fuzz::*;
    use crate::trace;

    #[derive(Default)]
    struct TestHook {

    }

    impl trace::Hook for TestHook {
        fn setup<T: trace::Tracer>(&mut self, _tracer: &mut T) {
            todo!()
        }

        fn handle_breakpoint<T: trace::Tracer>(&mut self, _tracer: &mut T) -> Result<bool, trace::TracerError> {
            todo!()
        }

        fn handle_trace(&self, _trace: &mut trace::Trace) -> Result<bool, trace::TracerError> {
            todo!()
        }

        fn patch_page(&self, _gva: u64) -> bool {
            todo!()
        }
    }

    #[derive(Default)]
    struct TestStrategy {
    }

    impl TestStrategy {

        pub fn new() -> Self {
            Self {
            }
        }

    }

    impl Strategy for TestStrategy {

        fn generate_new_input(&mut self, _data: &mut [u8], _corpus: &mut Corpus, _hint: &mut MutationHint) {

        }

        fn check_new_coverage(&mut self, _params: &Params, _trace: &mut trace::Trace) -> usize {
            0
        }

        fn get_coverage(&mut self) -> usize {
            0
        }

    }

    #[derive(Default)]
    struct TestTracer {

    }

    impl trace::Tracer for TestTracer {

        fn get_state(&mut self) -> Result<trace::ProcessorState, trace::TracerError> {
            todo!()
        }

        fn set_state(&mut self, _state: &trace::ProcessorState) -> Result<(), trace::TracerError> {
            Ok(())
        }

        fn run<H: trace::Hook>(&mut self, _params: &trace::Params, _hook: &mut H) -> Result<trace::Trace, trace::TracerError> {
            let trace = trace::Trace::new();
            Ok(trace)
        }

        fn restore_snapshot(&mut self) -> Result<usize, trace::TracerError> {
            Ok(0)
        }

        fn read_gva(&mut self, _cr3: u64, _vaddr: u64, data: &mut [u8]) -> Result<(), trace::TracerError> {
            let buf = vec![0u8; 0x60];
            data.clone_from_slice(&buf[..]);
            Ok(())
        }

        fn write_gva(&mut self, _cr3: u64, _vaddr: u64, _data: &[u8]) -> Result<(), trace::TracerError> {
            Ok(())
        }

        fn cr3(&mut self) -> Result<u64, trace::TracerError> {
            Ok(0x807000)
        }

        fn singlestep<H: trace::Hook>(&mut self, _params: &trace::Params, _hook: &mut H) -> Result<trace::Trace, trace::TracerError> {
            todo!()
        }

        fn add_breakpoint(&mut self, _address: u64) {
            todo!()
        }

        fn get_mapped_pages(&self) -> Result<usize, trace::TracerError> {
            Ok(0)
        }

        fn run_with_trace<'a, H: trace::Hook>(&'a mut self, _params: &'a trace::Params, _hook: &'a mut H, _trace: &mut trace::Trace) -> Result<(), trace::TracerError> {
            todo!()
        }
    }

    #[test]
    #[ignore]
    fn test_fuzzer() {

        let tmp = tempdir::TempDir::new("test_fuzzer").unwrap();
        let corpus = tmp.path().join("corpus");
        std::fs::create_dir(&corpus).unwrap();

        let mut fuzzer = Fuzzer::new(tmp.path()).unwrap();

        let params = Params {
            input_size: 0x60,
            max_duration: std::time::Duration::from_millis(60000),
            ..Default::default()
        };

        let mut tracer = TestTracer::default();
        let context = trace::ProcessorState::default();
        let trace_params = trace::Params::default();

        let mut strategy = TestStrategy::new();

        let mut corpus = Corpus::new(tmp.path());
        corpus.load().unwrap();

        let mut hook = TestHook::default();

        let stats = fuzzer.run(&mut corpus, &mut strategy, &params, &mut tracer, &context, &trace_params, &mut hook).unwrap();
        println!("{}", stats);

        tmp.close().unwrap();

    }


}