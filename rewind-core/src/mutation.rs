
use std::collections::BTreeSet;
use std::path::Path;
use std::io::Write;

use crate::{fuzz, trace};

struct BasicDatabase<'a> (&'a mut fuzz::Corpus);

impl <'a> basic_mutator::InputDatabase for BasicDatabase<'a> {

    fn num_inputs(&self) -> usize {
        self.0.members.len()

    }

    fn input(&self, idx: usize) -> Option<&[u8]> {
        let input = self.0.members.values().nth(idx);
        input.map(|i| i.as_ref())
    }
}

pub struct BasicStrategy {
    queue: Vec<Vec<u8>>,
    coverage: BTreeSet<u64>,
    mutator: basic_mutator::Mutator,
    last_refresh: std::time::Instant,
}

impl BasicStrategy {

    pub fn new(max_input_size: usize) -> Self {
        let mutator = basic_mutator::Mutator::new()
            // .seed(1337)
            .max_input_size(max_input_size);
        
        Self {
            queue: Vec::new(),
            coverage: BTreeSet::new(),
            mutator,
            last_refresh: std::time::Instant::now(),
        }
        
    }
}

impl fuzz::Strategy for BasicStrategy {

    // FIXME: select input with higher coverage first
    fn select_input(&mut self, corpus: &mut fuzz::Corpus) -> Option<Vec<u8>> { 
        if self.last_refresh.elapsed() > std::time::Duration::from_secs(5) {
            let path = std::path::Path::new(&corpus.workdir).join("hints.json");
            if path.exists() {
                match fuzz::MutationHint::load(path) {
                    Ok(rules) => {
                        self.mutator.accessed = rules.offsets.iter().map(|o| *o as usize).collect();
                        self.mutator.immediate_values = rules.immediates.iter().map(|o| o.to_le_bytes().to_vec()).collect();
                    }
                    Err(e) => {
                        warn!("can't load rules {}", e);
                    }
                }
            }
            self.last_refresh = std::time::Instant::now()
        }

        // need to populate with trace, need tracer as input
        // no need to use a queue, should return a ref to mutator.input?
        // really need to rewrite this:w
        if self.queue.is_empty() {
            let database = BasicDatabase(corpus);
            for (_hash, item) in database.0.members.iter() {
                // self.queue.push(item.clone());
                self.mutator.input.clear();
                self.mutator.input.extend_from_slice(item);

                // self.mutator.mutate(4, &database);
                self.mutator.mutate(4, &basic_mutator::EmptyDatabase);
                let mut mutant = self.mutator.input.clone();
                mutant.resize(item.len(), 0);
                self.queue.push(mutant);
            }
        };

        self.queue.pop()
    }

    // FIXME: need to path fuzzer path
    fn handle_execution(&mut self, _params: &fuzz::Params, data: &[u8], trace: &mut trace::Trace, corpus: &mut fuzz::Corpus) -> anyhow::Result<usize> {

        let new = trace.seen.difference(&self.coverage).count();

        // FIXME: need to load queue with that
        if new > 0 {
            let hash = fuzz::calculate_hash(data);
            let path = std::path::Path::new(&corpus.workdir)
                .join("corpus")
                .join(format!("{:x}.bin", hash));
            println!("discovered {} new address(es), adding file {:?} to corpus", new, path);
            let mut file = std::fs::File::create(path)?;
            file.write_all(data)?;
        }

        match trace.status {
            trace::EmulationStatus::Success => { }
            _ => {
                let hash = fuzz::calculate_hash(data);
                let path = std::path::Path::new(&corpus.workdir)
                    .join("crashes")
                    .join(format!("{:x}.bin", hash));
                println!("got abnormal exit {}, saving input to {:?}", trace.status, path);
                let mut file = std::fs::File::create(path)?;
                file.write_all(data)?;

            }
        }

        self.coverage.append(&mut trace.seen);
        Ok(new)

    }

    fn load_corpus(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn handle_new_corpus(&mut self, _data: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    // FIXME: need a save_stats to save even if it is not needed
    fn handle_stats(&mut self, workdir: &Path, stats: &mut crate::fuzz::Stats) -> anyhow::Result<()> {
        let elapsed = chrono::Utc::now() - stats.updated;
        if elapsed.to_std()? < std::time::Duration::from_secs(1) {
            return Ok(())
        }

        stats.updated = chrono::Utc::now();

        let path = workdir
            .join("instances")
            .join(format!("{}.json", stats.uuid));
            
        stats.save(path)
    }

    fn get_coverage(&mut self) -> usize {
        self.coverage.len()
    }

    fn get_queue_size(&mut self) -> usize {
        self.queue.len()
    }
}

