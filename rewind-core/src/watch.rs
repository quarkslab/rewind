use std::{fs::File, path::PathBuf};
use std::io::prelude::*;
use std::sync::mpsc;

use notify::Watcher;

pub enum Event {
    Create {path: PathBuf, data: Vec<u8>},
    Remove(PathBuf)
}

pub fn watch<S>(sender: &mpsc::Sender<Event>, path: S) -> notify::Result<()>
where S: Into<std::path::PathBuf> {
    // Create a channel to receive the events.
    // let (tx, rx) = unbounded();
    let (tx, rx) = mpsc::channel();

    // Automatically select the best implementation for your platform.
    // let mut watcher: notify::RecommendedWatcher = notify::Watcher::new_immediate(tx)?;
    let mut watcher = notify::watcher(tx, std::time::Duration::from_secs(1))?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(path.into(), notify::RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
            Ok(event) => {
                // info!("received event {:?}", event);
                match event {
                    notify::DebouncedEvent::Create(path) => {
                        let mut file = File::open(&path)?;
                        let mut data = Vec::new();
                        file.read_to_end(&mut data)?;
                        let event = Event::Create {
                            path,
                            data
                        };
                        sender.send(event).map_err(|e| {
                            let e = format!("{:?}", e);
                            notify::Error::Generic(e)
                        })?;
                    }

                    notify::DebouncedEvent::Remove(path) => {
                        let event = Event::Remove(path);
                        sender.send(event).map_err(|e| {
                            let e = format!("{:?}", e);
                            notify::Error::Generic(e)
                        })?;
                    }

                    _ => {

                    }
                }
            },
            Err(err) => {
                let e = format!("{:?}", err);
                return Err(notify::Error::Generic(e));
            }
        };
    }

}
