use std::{io::{Read, Write}, path::PathBuf, time::Duration};
use std::collections::{HashMap, BTreeSet};
use std::thread;
use std::sync::mpsc;
use std::time::Instant;

use event::KeyEvent;
use thiserror::Error;

use memmap::MmapOptions;

use rewind_core::{fuzz, mem::X64VirtualAddressSpace, mutation, snapshot::Snapshot, trace::{self, Tracer}, watch};
use rewind_system::{System, PdbStore};
use rewind_snapshot::{SnapshotKind, FileSnapshot, DumpSnapshot};

pub use crossterm::{
    event::{self, Event, KeyCode, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

pub use tui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
    text::{Span, Spans},
    symbols,
    widgets::canvas::{Canvas, Line, Map, MapResolution, Rectangle},
    widgets::{
        Axis, BarChart, Block, Borders, Chart, Dataset, Gauge, LineGauge, List, ListItem, ListState,
        Paragraph, Row, Cell, Sparkline, Table, Tabs, Wrap, TableState, BorderType,
    },
    style::{Color, Modifier, Style},
    backend::CrosstermBackend,
    Terminal
};

use crate::widget::{ActiveWidget, CorpusFile, Function};
use crate::app::App;

#[derive(Error, Debug)]
pub enum TuiError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("terminal error: {0}")]
    TermError(#[from] crossterm::ErrorKind),
    
    #[error("channel error: {0}")]
    FlumeError(#[from] flume::SendError<Control>),

    #[error("channel error: {0}")]
    FlumeError2(#[from] flume::SendError<Message>),

    #[error("channel error: {0}")]
    FlumeRecvError(#[from] flume::RecvError),

    #[error("core error: {0}")]
    CoreError(#[from] rewind_core::error::GenericError),

    #[error("store error: {0}")]
    StoreError(#[from] rewind_system::StoreError),

    #[error("system error: {0}")]
    SystemError(#[from] rewind_system::SystemError),

    #[error("snapshot error: {0}")]
    SnapshotError(#[from] rewind_core::snapshot::SnapshotError),

    #[error("tracer error: {0}")]
    TracerError(#[from] rewind_core::trace::TracerError),
}


/// Global coverage (addresses, functions and modules) from corpus entries
#[derive(Debug)]
pub struct Collection {
    /// Coverage
    pub coverage: BTreeSet<u64>,
    /// Corpus
    pub corpus: HashMap<std::path::PathBuf, CorpusFile>,
    /// Modules
    pub modules: HashMap<String, usize>,
    /// Functions
    pub functions: HashMap<String, Function>,
}

impl Collection {

    /// Constructor
    pub fn new() -> Self {
        Self {
            coverage: BTreeSet::new(),
            modules: HashMap::new(),
            functions: HashMap::new(),
            corpus: HashMap::new(),
        }
    }

}

impl Default for Collection {
    fn default() -> Self {
        Self::new()
    }
}

pub fn setup_terminal() -> Result<std::io::Stdout, TuiError> {
    let mut stdout_val = std::io::stdout();
    execute!(stdout_val, EnterAlternateScreen, EnableMouseCapture)?;
    enable_raw_mode()?;

    Ok(stdout_val)
}

pub fn cleanup_terminal(
    terminal: &mut tui::terminal::Terminal<tui::backend::CrosstermBackend<std::io::Stdout>>,
) -> Result<(), TuiError> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, app: &mut App) {
    let chunks = Layout::default()
        .constraints(
            [
                Constraint::Percentage(6),
                Constraint::Percentage(10),
                Constraint::Percentage(20),
                Constraint::Percentage(30),
                Constraint::Percentage(17),
                Constraint::Percentage(17),
            ]
            .as_ref(),
        )
        .split(f.size());

    draw_statistics(f, chunks[0], app);
    draw_instances(f, chunks[1], app);
    draw_corpus(f, chunks[2], app);
    draw_coverage(f, chunks[3], app);
    draw_crashes(f, chunks[4], app);
    draw_logs(f, chunks[5], app);

}

fn draw_statistics(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let active_instances: Vec<&fuzz::Stats> = app.instances_widget.instances.iter().filter(|i| {
        i.last_updated() < std::time::Duration::from_secs(10)
    }).collect();

    let iterations = active_instances.iter().fold(0, |a, s| {
        a + s.iterations
    });

    let execs = active_instances.iter().fold(0, |a, s| {
        a + s.iterations / (s.updated - s.start).num_seconds() as u64
    });

    let coverage = app.stats_widget.coverage;

    let text = vec![
        Spans::from(format!("{} iterations, {} exec/s, coverage {}", iterations, execs, coverage)),
    ];

    let title_style = Style::default()
            .add_modifier(Modifier::BOLD);
    
    // FIXME: add fuzzing directory and snapshot path
    let title = Span::styled(
        "Statistics",
        title_style
    );

    let block = Block::default().borders(Borders::ALL).title(title);

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);

}

fn draw_instances(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let up_style = Style::default();
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let rows: Vec<Row> = app.instances_widget.instances.iter().filter_map(|s| {
        if s.last_updated() < std::time::Duration::from_secs(10) {
            let elapsed = (s.updated - s.start).to_std().unwrap();
            let num_seconds = std::cmp::max(1, (s.updated - s.start).num_seconds());
            let execs = s.iterations / num_seconds as u64;
            Some(Row::new(vec![format!("{}", s.uuid),
                        format!("{:?}", elapsed),
                        format!("{}", s.iterations),
                        format!("{}", execs),
                        ]).style(up_style))
        } else {
            None
        } 
    }).collect();

    let border_type = match app.active_widget {
        ActiveWidget::Instances => BorderType::Thick,
        _ => BorderType::Plain
    };
 
    let title_style = match app.active_widget {
        ActiveWidget::Instances => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Actives instances ({} fuzzer(s))", rows.len());
    let title = Span::styled(
        title,
        title_style
    );

    let header_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);


    let table = Table::new(rows)
        .header(
            Row::new(vec!["Instance", "Time", "Iterations", "Exec/s"])
                .style(header_style)
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ]);

    f.render_stateful_widget(table, area, &mut app.instances_widget.state);
}

fn draw_corpus(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let rows = app.corpus_widget.files.iter().map(|item| {
        Row::new(vec![format!("{}", item.path.display()),
                      format!("{}", item.count),
                      format!("{}", item.seen),
                      format!("{:?}", item.duration),
                      format!("{}", item.modified_pages),
                      ])
    });

    // FIXME: move this to a function
    let border_type = match app.active_widget {
        ActiveWidget::Corpus => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        ActiveWidget::Corpus => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Corpus ({} file(s))", app.corpus_widget.files.len());
    let title = Span::styled(
        title,
        title_style
    );

    let table = Table::new(rows)
        .header(
            Row::new(vec!["File", "Instructions", "Unique", "Time", "Modified pages"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ]);

    f.render_stateful_widget(table, area, &mut app.corpus_widget.state);
}

fn draw_coverage(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .constraints(
            [
                // Constraint::Percentage(50),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .split(area);
    // draw_chart(f, chunks[0], app);
    draw_functions(f, chunks[0], app);
}

// fn _draw_chart(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
//     // let points: Vec<(f64, f64)> = vec![(0.0, 0.0), (1.0, 2.0) , (4.0, 4.0), (10.0, 20.0), (3.0, 4.0)];
//     let datasets = vec![
//         Dataset::default()
//             .name("unique instructions")
//             .marker(symbols::Marker::Dot)
//             .style(Style::default().fg(Color::Cyan))
//             .data(&app.points),
//     ];
//     let chart = Chart::new(datasets)
//         .block(
//             Block::default()
//                 .title(Span::styled(
//                     "Coverage",
//                     Style::default()
//                         .fg(Color::Cyan)
//                         .add_modifier(Modifier::BOLD),
//                 ))
//                 .borders(Borders::ALL),
//         )
//         .x_axis(
//             Axis::default()
//                 .title("Iterations")
//                 .style(Style::default().fg(Color::Gray))
//                 // .bounds()
//                 .bounds([0.0, 20.0])
//                 // .labels(x_labels),
//                 .labels(vec![
//                     // Span::styled("-20", Style::default().add_modifier(Modifier::BOLD)),
//                     Span::raw("0"),
//                     Span::styled("20", Style::default().add_modifier(Modifier::BOLD)),
//                 ]),
//         )
//         .y_axis(
//             Axis::default()
//                 .title("Coverage")
//                 .style(Style::default().fg(Color::Gray))
//                 .bounds([0.0, 20.0])
//                 .labels(vec![
//                     // Span::styled("-20", Style::default().add_modifier(Modifier::BOLD)),
//                     Span::raw("0"),
//                     Span::styled("20", Style::default().add_modifier(Modifier::BOLD)),
//                 ]),
//         );
//     f.render_widget(chart, area);
// }

fn draw_functions(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let rows = app.coverage_widget.functions.iter().map(|item| {
        Row::new(vec![item.module.to_string(),
                      item.name.to_string(),
                      format!("{}", item.coverage)])
    });

    let border_type = match app.active_widget {
        ActiveWidget::Coverage => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        ActiveWidget::Coverage => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Coverage ({} function(s))", app.coverage_widget.functions.len());

    let title = Span::styled(
        title,
        title_style
    );

    let table = Table::new(rows)
        .header(
            Row::new(vec!["Module", "Function", "Coverage"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(20),
            Constraint::Percentage(70),
            Constraint::Percentage(10),
        ]);

    f.render_stateful_widget(table, area, &mut app.coverage_widget.state);
}

fn draw_crashes(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let rows = app.crashes_widget.files.iter().map(|item| {
        Row::new(vec![format!("{}", item.path.display()),
                      format!("{}", item.count),
                      format!("{}", item.seen),
                      format!("{:?}", item.duration),
                      format!("{}", item.modified_pages)
                      ])
    });

    let border_type = match app.active_widget {
        ActiveWidget::Crash => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        ActiveWidget::Crash => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Crashes ({} file(s))", app.crashes_widget.files.len());

    let title = Span::styled(
        title,
        title_style
    );

    let table = Table::new(rows)
        .header(
            Row::new(vec!["File", "Instructions", "Unique", "Time", "Modified pages"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ]);

    f.render_stateful_widget(table, area, &mut app.crashes_widget.state);
}

fn draw_logs(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let title_style = Style::default();

    let title = Span::styled(
        "Logs",
        title_style
    );

    let block = Block::default().borders(Borders::ALL).title(title);

    let logs: Vec<ListItem> = app
        .logs_widget
        .items
        .iter()
        .map(|s| {
            let content = vec![Spans::from(vec![
                Span::raw(s),
            ])];
            ListItem::new(content)
        })
        .collect();
    let logs = List::new(logs).block(block);
    f.render_stateful_widget(logs, area, &mut app.logs_widget.state);

}

fn replay_file<H: trace::Hook>(tx: &flume::Sender<Message>,
        path: &std::path::Path,
        tracer: &mut rewind_bochs::BochsTracer<SnapshotKind>,
        context: &trace::ProcessorState,
        trace_params: &trace::Params,
        fuzz_params: &fuzz::Params) -> Result<trace::Trace, TuiError> {

    tx.send(Message::Log(format!("replaying input {}", path.display())))?;

    let mut file = std::fs::File::open(&path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let cr3 = context.cr3;

    match Tracer::write_gva(tracer, cr3, fuzz_params.input, &data) {
        Ok(()) => {}
        Err(e) => {
            return Err(TuiError::TracerError(e));
        }
    }

    tracer.set_state(&context)?;

    let mut hook = H::default();
    hook.setup(tracer);

    let start = Instant::now();

    let mut trace = tracer.run(&trace_params, &mut hook)?;

    let end = Instant::now();
    let t = end - start;

    let pages = tracer.get_mapped_pages()?;
    let _mem = rewind_core::helpers::convert((pages * 0x1000) as f64);
   
    tx.send(Message::Log(format!("executed {} instruction(s) in {:?} ({:?})", trace.coverage.len(), t, trace.status)))?;

    hook.handle_trace(&mut trace)?;

    Ok(trace)

}

#[allow(clippy::too_many_arguments)]
fn update_coverage<S: Snapshot + X64VirtualAddressSpace>(workdir: &PathBuf, system: &System<S>, store: &mut PdbStore, corpus_path: PathBuf, fuzz_params: &fuzz::Params, mut trace: trace::Trace, modified_pages: usize, collection: &mut Collection, hints: &mut mutation::MutationHint, tx: &flume::Sender<Message> ) -> Result<(), TuiError> {

    let mut corpus_file = CorpusFile::new(corpus_path.file_name().unwrap());
    corpus_file.seen = trace.seen.len() as u64;
    corpus_file.count = trace.coverage.len() as u64;

    corpus_file.modified_pages = modified_pages;

    corpus_file.duration = match (trace.start, trace.end) {
        (Some(start), Some(end)) => end - start,
        _ => Duration::from_millis(0)
    };

    let functions = collection.functions.clone();
    tx.send(Message::Coverage(functions))?;

    hints.immediates.append(&mut trace.immediates);
    let address = fuzz_params.input;
    let size = fuzz_params.input_size;
    let filtered = trace.mem_access.iter()
        .filter(|a| {
            a.1 >= address && a.1 < address + size
        })
        .map(|a| {
            a.1 - address
        });

    hints.offsets.extend(filtered);

    if trace.seen.is_subset(&collection.coverage) {
        tx.send(Message::Log(format!("removing {}", corpus_path.display())))?;
        std::fs::remove_file(&corpus_path)?;
    } else {
        match trace.status {
            trace::EmulationStatus::Success => {
                tx.send(Message::Corpus(corpus_file))?;
            },
            _ => {
                tx.send(Message::Crash(corpus_file))?;
            }
        }

        trace.save(workdir.join("traces").join(format!("{}.json", corpus_path.file_name().unwrap().to_str().unwrap())))?;
        parse_trace(collection, &mut trace, &system, store)?;
    }

    Ok(())
}

fn collect_coverage_thread<H: trace::Hook>(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) -> Result<(), TuiError> {
    loop {

        let control = control_rx.recv()?;

        match control {
            Control::Start((workdir, store)) => {
                let input_path = workdir.join("params.json");
                let fuzz_params = fuzz::Params::load(&input_path)?;

                let snapshot_path = &fuzz_params.snapshot_path;

                let buffer;
                let snapshot = if snapshot_path.join("mem.dmp").exists() {
                    let dump_path = snapshot_path.join("mem.dmp");

                    let fp = std::fs::File::open(&dump_path)?;
                    buffer = unsafe { MmapOptions::new().map(&fp)? };

                    let snapshot = DumpSnapshot::new(&buffer)?;
                    SnapshotKind::DumpSnapshot(snapshot)
                } else {
                    let snapshot = FileSnapshot::new(&snapshot_path)?;
                    SnapshotKind::FileSnapshot(snapshot)
                };

                let context_path = snapshot_path.join("context.json");
                let context = trace::ProcessorState::load(&context_path)?;

                let params_path = snapshot_path.join("params.json");
                let mut trace_params = trace::Params::load(&params_path)?;
                trace_params.save_context = true;

                let mut tracer = rewind_bochs::BochsTracer::new(&snapshot);

                let mut system = System::new(&snapshot)?;
                system.load_modules()?;

                let path = &store;
                if !path.exists() {
                    std::fs::create_dir(&path)?;
                    std::fs::create_dir(path.join("binaries"))?;
                    std::fs::create_dir(path.join("symbols"))?;
                }

                let mut store = PdbStore::new(path)?;

                let mut hints = mutation::MutationHint::new();

                let mut collection = Collection::new();

                tx.send(Message::Log("loading corpus".to_string()))?;
                let path = workdir.join("corpus");
                let mut entries = std::fs::read_dir(&path)?
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                let path = workdir.join("crashes");
                let crash_entries = std::fs::read_dir(&path)?
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                entries.extend(crash_entries);
                entries.sort();

                for path in entries {
                    if path.extension() == Some(std::ffi::OsStr::new("bin")) {
                        let trace = replay_file::<H>(&tx, &path, &mut tracer, &context, &trace_params, &fuzz_params)?;
                        let modified_pages = tracer.restore_snapshot()?;
                        update_coverage(&workdir, &system, &mut store, path, &fuzz_params, trace, modified_pages, &mut collection, &mut hints, &tx)?;
                    }
                }
                let path = workdir.join("snapshot");
                snapshot.save(path)?;
                 
                tx.send(Message::TotalCoverage(collection.coverage.len()))?;
                tx.send(Message::Log(format!("updating mutation hints: immediates {}, offsets {}", hints.immediates.len(), hints.offsets.len())))?;
                let path = workdir.join("hints.json");
                hints.save(&path)?;
                    
                let (watcher_tx, watcher_rx) = mpsc::channel();
                let corpus_path = workdir.join("corpus");
                thread::spawn(move || {
                    loop {
                        let result = watch::watch(&watcher_tx, &corpus_path);
                        println!("{:?}", result);
                    }
                });

                loop {
                    if let Ok(event)  = watcher_rx.recv() {
                        match event {
                            watch::Event::Create { path, .. } => {
                                let trace = replay_file::<H>(&tx, &path, &mut tracer, &context, &trace_params, &fuzz_params)?;
                                let modified_pages = tracer.restore_snapshot()?;
                                update_coverage(&workdir, &system, &mut store, path, &fuzz_params, trace, modified_pages, &mut collection, &mut hints, &tx)?;
                                tx.send(Message::TotalCoverage(collection.coverage.len()))?;
                                tx.send(Message::Log(format!("updating mutation hints: immediates {}, offsets {}", hints.immediates.len(), hints.offsets.len())))?;
                                let path = workdir.join("hints.json");
                                hints.save(&path)?;
                                snapshot.save(workdir.join("snapshot"))?;
                            }
                            watch::Event::Remove(_path) => {

                            }
                        }
                    }
                }
            },
            _ => {
                tx.send(Message::Log("stopping coverage thread".to_string()))?;
                return Ok(())
            }
        }

    }

}

#[derive(Debug)]
pub enum Control {
    Start((std::path::PathBuf, std::path::PathBuf)),
    Stop,
}

#[derive(Debug)]
pub enum Message {
    Input(KeyEvent),
    Tick,
    Instances(HashMap<std::path::PathBuf, fuzz::Stats>),
    Log(String),
    Coverage(HashMap<String, Function>),
    TotalCoverage(usize),
    Corpus(CorpusFile),
    Crash(CorpusFile),
}

fn start_coverage_collector_thread<H: trace::Hook>(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) {
    thread::spawn( move || {
        let result = collect_coverage_thread::<H>(control_rx, tx.clone());
        tx.send(Message::Log(format!("error: thread returned {:?}", result))).unwrap();
    });
}

fn start_instances_collector_thread(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) {
    thread::spawn( move || {
        let result = collect_instances_thread(control_rx, tx.clone());
        tx.send(Message::Log(format!("error: thread returned {:?}", result))).unwrap();
    });
 
}

fn collect_instances_thread(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) -> Result<(), TuiError> {
    loop {
        let control = control_rx.recv()?;
        match control {
            Control::Start((workdir, _store)) => {
                loop {
                    let path = workdir.join("instances");
                    let mut entries = std::fs::read_dir(&path)?
                        .map(|res| res.map(|e| e.path()))
                        .collect::<Result<Vec<_>, std::io::Error>>()?;

                    entries.sort();

                    let mut instances = HashMap::new();
                    for path in entries {
                        if path.extension() == Some(std::ffi::OsStr::new("json")) {
                            let stats = fuzz::Stats::load(&path)?;

                            let filename = path.to_path_buf();
                            instances.insert(filename, stats);
                        }
                    }
                        
                    tx.send(Message::Instances(instances))?;

                    if !control_rx.is_empty() {
                        break
                    }

                    std::thread::sleep(std::time::Duration::from_secs(2));
                }

            },
            _ => {
                tx.send(Message::Log("stopping thread".to_string()))?;
                return Ok(())
            }
        }
 
    }
}


/// Display TUI
pub fn display_tui<H: trace::Hook>(workdir: PathBuf, store: PathBuf) -> Result<(), TuiError> {
    let (tx, rx) = flume::unbounded();
    let (control_instance_tx, control_instance_rx) = flume::unbounded();
    let (control_coverage_tx, control_coverage_rx) = flume::unbounded();

    start_coverage_collector_thread::<H>(control_coverage_rx, tx.clone());
    start_instances_collector_thread(control_instance_rx, tx.clone());

    control_coverage_tx.send(Control::Start((workdir.clone(), store.clone())))?;
    control_instance_tx.send(Control::Start((workdir, store)))?;

    let stdout_val = setup_terminal()?;

    let backend = CrosstermBackend::new(stdout_val);

    let mut terminal = Terminal::new(backend)?;

    // polling thread
    thread::spawn(move || {
        loop {
            if let Event::Key(key) = event::read().unwrap() {
                tx.send(Message::Input(key)).unwrap();
            }
        }
    });

    let mut app = App::new();

    terminal.clear()?;
    terminal.hide_cursor()?;

     loop {
        terminal.draw(|f| draw(f, &mut app))?;
        match rx.recv()? {
            Message::Input(event) => match event.code {
                KeyCode::Char('q') => {
                    cleanup_terminal(&mut terminal)?;
                    break;
                }
                KeyCode::Char(c) => app.on_key(c),
                KeyCode::Left => app.on_left(),
                KeyCode::Right => app.on_right(),
                KeyCode::Tab => app.on_tab(),
                KeyCode::Up => app.on_up(),
                KeyCode::Down => app.on_down(),
                KeyCode::PageUp => app.on_page_up(),
                KeyCode::PageDown => app.on_page_down(),
                _ => {}
            },
            Message::Tick => {
                app.on_tick();
            },
            Message::Coverage(c) => {
                app.on_collect(c);
            },
            Message::TotalCoverage(size) => {
                app.on_total_coverage(size);
            }
            Message::Log(l) => {
                app.on_log(l)
            },
            Message::Instances(i) => {
                app.on_instance(i)
            },
            Message::Corpus(i) => {
                app.on_corpus(i)
            },
            Message::Crash(i) => {
                app.on_crash(i)
            },
        }

    }

    Ok(())
}

// FIXME: to rename => collect trace coverage, should return Coverage, should be in system
/// Update collection with coverage from trace
#[allow(clippy::if_same_then_else)]
pub fn parse_trace<S: Snapshot + X64VirtualAddressSpace>(collection: &mut Collection, trace: &mut trace::Trace, system: &System<S>, store: &mut PdbStore) -> Result<(), TuiError> {
    for &address in trace.seen.difference(&collection.coverage) {
        if let Some(module) = system.get_module_by_address(address) {
            *collection.modules.entry(module.name.clone()).or_insert_with(|| {

                // FIXME: need a fn in system.rs
                // println!("download pe");
                if let Ok(info) = system.get_file_information(module) {
                    if store.download_pe(&module.name, &info).is_ok() {
                        // println!("download pe... ok");
                    } else {
                        // println!("error during download");
                    }
                }

                // println!("download pdb");
                if let Ok(info) = system.get_debug_information(module) {
                    let (name, guid) = info.into();
                    if store.download_pdb(&name, &guid).is_ok() && store.load_pdb(module.base, &name, &guid).is_ok() {
                        // println!("download pdb... ok");
                    } else {
                        // println!("error during download");
                    }
                }

                0
            }) += 1;

            if let Some(symbol) = store.resolve_address(address) {
                // FIXME: get size of symbol and size of func
                let name = format!("{}!{}", symbol.module, symbol.name);
                collection.functions.entry(name)
                    .and_modify(|f| f.coverage += 1)
                    .or_insert_with(|| {
                        Function::new(symbol.module, symbol.name, 1)
                    });
            }
        }
    }

    collection.coverage.append(&mut trace.seen);

    Ok(())
}