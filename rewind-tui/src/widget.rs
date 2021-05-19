
use std::time::Duration;

pub use tui::widgets::{
    Axis, BarChart, Block, Borders, Chart, Dataset, Gauge, LineGauge, List, ListItem, ListState,
    Paragraph, Row, Cell, Sparkline, Table, Tabs, Wrap, TableState, BorderType,
};

use rewind_core::fuzz;
 
pub (crate) struct StatsWidget {
    pub coverage: u64

}

impl StatsWidget {

    pub fn new() -> Self {
        Self {
            coverage: 0
        }
    }

}


pub (crate) struct InstanceWidget {
    pub state: TableState,
    pub instances: Vec<fuzz::Stats>,
}

impl InstanceWidget {
    
    pub fn new() -> Self {
        Self {
            state: TableState::default(),
            instances: Vec::new(),
        }
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.instances.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.instances.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}
pub (crate) struct CorpusWidget {
    pub state: TableState,
    pub files: Vec<CorpusFile>,
}

impl CorpusWidget {

    pub fn new() -> Self {
        Self {
            state: TableState::default(),
            files: Vec::new(),
        }
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.files.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.files.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

pub (crate) struct CoverageWidget {
    pub state: TableState,
    pub functions: Vec<Function>,
}

impl CoverageWidget {

    pub fn new() -> Self {
        Self {
            state: TableState::default(),
            functions: Vec::new(),
        }
    }

    pub fn next(&mut self) {
        if self.functions.is_empty() {
            return
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.functions.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        if self.functions.is_empty() {
            return
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.functions.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}
pub (crate) struct CrashesWidget {
    pub state: TableState,
    pub files: Vec<CorpusFile>,
}

impl CrashesWidget {

    pub fn new() -> Self {
        Self {
            state: TableState::default(),
            files: Vec::new(),
        }
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.files.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.files.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}
pub (crate) struct LogsWidget {
    pub state: ListState,
    pub items: Vec<String>,
}

impl LogsWidget {

    pub fn new() -> Self {
        Self {
            state: ListState::default(),
            items: Vec::new(),
        }
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn _previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

pub (crate) enum ActiveWidget {
    Instances,
    Corpus,
    Coverage,
    Crash,
}

impl ActiveWidget {

    pub fn next(&self) -> Self {
        match self {
            Self::Instances => Self::Corpus,
            Self::Corpus => Self::Coverage,
            Self::Coverage => Self::Crash,
            Self::Crash => Self::Instances,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct CorpusFile {
    pub path: std::path::PathBuf,
    pub seen: u64,
    pub count: u64,
    pub duration: Duration,
    pub modified_pages: usize,
    // instructions count
    // time
}

impl CorpusFile {

    pub fn new<P>(path: P) -> Self
    where P: Into<std::path::PathBuf> {
        Self {
            path: path.into(),
            seen: 0,
            count: 0,
            duration: Duration::from_secs(0),
            modified_pages: 0,
        }
    }
}



#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Function {
    pub module: String,
    pub name: String,
    pub coverage: u64,
    size: u64,
}

impl Function {

    pub fn new(module: String, name: String, coverage: u64) -> Self {
        Self {
            module,
            name,
            coverage,
            size: 0 
        }
    }
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}!{}", self.module, self.name)
    }
}

