use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;

use crossbeam_channel::unbounded;
use notify;
use notify::Watcher;
// ::{RecommendedWatcher, RecursiveMode, Result, Watcher};

pub fn watch<S>(channel: mpsc::Sender<Vec<u8>>, path: S) -> notify::Result<()>
where S: Into<std::path::PathBuf> {
    // Create a channel to receive the events.
    let (tx, rx) = unbounded();

    // Automatically select the best implementation for your platform.
    let mut watcher: notify::RecommendedWatcher = notify::Watcher::new_immediate(tx)?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(path.into(), notify::RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
            Ok(event) => match event {
                notify::RawEvent {
                    path: Some(path),
                    op: Ok(_mod),
                    cookie: _,
                } => {
                    let mut file = File::open(&path)?;
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)?;
                    match channel.send(data) {
                        _ => {}
                    }
                }
                _ => {}
            },
            Err(err) => {
                error!("watch error: {:?}", err);
                break;
            }
        };
    }

    Ok(())
}
