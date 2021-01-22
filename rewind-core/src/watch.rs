use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;

use notify::Watcher;

pub fn watch<S>(sender: &mpsc::Sender<Vec<u8>>, path: S) -> notify::Result<()>
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
                if let notify::DebouncedEvent::Create(path) = event {
                    let mut file = File::open(&path)?;
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)?;
                    sender.send(data).map_err(|e| {
                        let e = format!("{:?}", e);
                        notify::Error::Generic(e)
                    })?;
                }
            },
            Err(err) => {
                let e = format!("{:?}", err);
                return Err(notify::Error::Generic(e));
            }
        };
    }

}
