use std::{io::Write, path::PathBuf};
use std::collections::{HashMap, BTreeSet};

use fuzz::Stats;
use thiserror::Error;

use rewind_core::fuzz;

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

#[derive(Error, Debug)]
pub enum TuiError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("terminal error: {0}")]
    TermError(#[from] crossterm::ErrorKind),


}

pub enum TuiEvent<I> {
    Input(I),
    Tick,
    Instances(HashMap<std::path::PathBuf, fuzz::Stats>),
    Log(String),
    Coverage(HashMap<String, Function>),
    Corpus(CorpusFile),
    Crash(CorpusFile),
}


pub struct StatsWidget {
    pub coverage: u64

}

impl StatsWidget {

    fn new() -> Self {
        Self {
            coverage: 0
        }
    }

}


struct InstanceWidget {
    state: TableState,
    instances: Vec<fuzz::Stats>,
}

impl InstanceWidget {
    fn new() -> Self {
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
 
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct CorpusFile {
    pub path: std::path::PathBuf,
    pub seen: u64,
    pub count: u64,
    // instructions count
    // time
}

impl CorpusFile {

    pub fn new<P>(path: P) -> Self
    where P: Into<std::path::PathBuf> {
        Self {
            path: path.into(),
            seen: 0,
            count: 0
        }
    }
}

struct CorpusWidget {
    state: TableState,
    files: Vec<CorpusFile>,
}

impl CorpusWidget {
    fn new() -> Self {
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Function {
    module: String,
    name: String,
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

struct CoverageWidget {
    state: TableState,
    functions: Vec<Function>,
}

impl CoverageWidget {
    fn new() -> Self {
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
struct CrashesWidget {
    state: TableState,
    files: Vec<CorpusFile>,
}

impl CrashesWidget {
    fn new() -> Self {
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


enum Widget {
    Instances,
    Corpus,
    Coverage,
    Crash,
}

impl Widget {

    fn next(&self) -> Self {
        match self {
            Self::Instances => Self::Corpus,
            Self::Corpus => Self::Coverage,
            Self::Coverage => Self::Crash,
            Self::Crash => Self::Instances,
        }
    }
}

#[derive(Debug)]
pub struct Collection {
    pub coverage: BTreeSet<u64>,
    pub corpus: HashMap<std::path::PathBuf, CorpusFile>,
    pub modules: HashMap<String, usize>,
    pub functions: HashMap<String, Function>,
}

impl Collection {

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

struct LogsWidget {
    state: ListState,
    items: Vec<String>,
}

impl LogsWidget {
    fn new() -> Self {
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

pub struct App {
    stats_widget: StatsWidget,
    instances_widget: InstanceWidget,
    corpus_widget: CorpusWidget,
    coverage_widget: CoverageWidget,
    crashes_widget: CrashesWidget,
    logs_widget: LogsWidget,
    active_widget: Widget,
    // points: Vec<(f64, f64)>,
    // ticks: usize,
}

impl App {

    pub fn new() -> Self {
        Self {
            stats_widget: StatsWidget::new(),
            instances_widget: InstanceWidget::new(),
            corpus_widget: CorpusWidget::new(),
            coverage_widget: CoverageWidget::new(),
            crashes_widget: CrashesWidget::new(),
            logs_widget: LogsWidget::new(),
            active_widget: Widget::Instances,
            // points: Vec::new(),
            // ticks: 0,
        }

    }

    pub fn on_key(&mut self, _c: char) {
    }

    pub fn on_collect(&mut self, functions: HashMap<String, Function>) {
        // self.stats_widget.coverage = collection.coverage.len() as u64;

        self.coverage_widget.functions.clear();
        self.coverage_widget.functions.extend(functions.values().cloned());
        self.coverage_widget.functions.sort();

    }

    pub fn on_corpus(&mut self, file: CorpusFile) {
        self.corpus_widget.files.push(file);
        self.corpus_widget.files.sort_by(|a, b| { b.count.cmp(&a.count) });
    }

    pub fn on_crash(&mut self, file: CorpusFile) {
        self.crashes_widget.files.push(file);
        self.crashes_widget.files.sort_by(|a, b| { b.count.cmp(&a.count) });
    }

    pub fn on_instance(&mut self, instances: HashMap<PathBuf, Stats>) {
        self.instances_widget.instances.clear();
        self.instances_widget.instances.extend(instances.values().cloned());
        // FIXME: short by time, remove old instances ?
        self.instances_widget.instances.sort_by(|a, b| { a.uuid.cmp(&b.uuid) });
    }

    pub fn on_log(&mut self, log: String) {
        self.logs_widget.items.push(log);
        if self.logs_widget.items.len() > 50 {
            self.logs_widget.items.remove(0);
        }
        self.logs_widget.next();
    }

    pub fn on_tick(&mut self) {

    }

    pub fn on_tab(&mut self) {
        let widget = self.active_widget.next();
        self.active_widget = widget;

    }

    pub fn on_up(&mut self) {
        match self.active_widget {
            Widget::Instances => {
                self.instances_widget.previous()
            },
            Widget::Corpus => {
                self.corpus_widget.previous()
            },
            Widget::Coverage => {
                self.coverage_widget.previous()
            },
            Widget::Crash => {
                self.crashes_widget.previous()
            }
        }

    }

    pub fn on_page_up(&mut self) {
        match self.active_widget {
            Widget::Instances => {
                self.instances_widget.previous()
            },
            Widget::Corpus => {
                self.corpus_widget.previous()
            },
            Widget::Coverage => {
                self.coverage_widget.previous()
            },
            Widget::Crash => {
                self.crashes_widget.previous()
            }
        }

    }

    pub fn on_down(&mut self) {
        match self.active_widget {
            Widget::Instances => {
                self.instances_widget.next()
            },
            Widget::Corpus => {
                self.corpus_widget.next()
            },
            Widget::Coverage => {
                self.coverage_widget.next()
            },
            Widget::Crash => {
                self.crashes_widget.next()
            }
        }
    }

    pub fn on_page_down(&mut self) {
        match self.active_widget {
            Widget::Instances => {
                self.instances_widget.next()
            },
            Widget::Corpus => {
                self.corpus_widget.next()
            },
            Widget::Coverage => {
                self.coverage_widget.next()
            },
            Widget::Crash => {
                self.crashes_widget.next()
            }
        }
    }

    pub fn on_right(&mut self) {

    }

    pub fn on_left(&mut self) {

    }

}

impl Default for App {

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

pub fn draw(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, app: &mut App) {
    let chunks = Layout::default()
        .constraints(
            [
                Constraint::Percentage(5),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(15),
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
    
    // FIXME: rajouter le repertoire de fuzzing
    // afficher le snapshot (fuzz_params)
    let title = Span::styled(
        "Statistics",
        title_style
    );

    let block = Block::default().borders(Borders::ALL).title(title);

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);

}

fn draw_instances(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {

    let up_style = Style::default().fg(Color::Green);

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let failure_style = Style::default();
        // .add_modifier(Modifier::CROSSED_OUT);

    let rows = app.instances_widget.instances.iter().map(|s| {
        let style = if s.last_updated() < std::time::Duration::from_secs(10) {
            up_style
        } else {
            failure_style
        };

        let elapsed = (s.updated - s.start).to_std().unwrap();
        let num_seconds = std::cmp::max(1, (s.updated - s.start).num_seconds());
        let execs = s.iterations / num_seconds as u64;
        Row::new(vec![format!("{}", s.uuid),
                      format!("{:?}", elapsed),
                      format!("{}", s.iterations),
                      format!("{}", execs),
                      format!("{}", s.coverage),
                      ]).style(style)
    });

    let border_type = match app.active_widget {
        Widget::Instances => BorderType::Thick,
        _ => BorderType::Plain
    };
 
    let title_style = match app.active_widget {
        Widget::Instances => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Instances ({} fuzzer(s))", app.instances_widget.instances.len());
    let title = Span::styled(
        title,
        title_style
    );

    let header_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);


    let table = Table::new(rows)
        .header(
            Row::new(vec!["Instance", "Time", "Iterations", "Exec/s", "Coverage"])
                .style(header_style)
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ]);

    f.render_stateful_widget(table, area, &mut app.instances_widget.state);
}

fn draw_corpus(f: &mut Frame<CrosstermBackend<std::io::Stdout>>, area: Rect, app: &mut App) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let rows = app.corpus_widget.files.iter().map(|item| {
        Row::new(vec![format!("{}", item.path.display()),
                      format!("{}", item.count),
                      format!("{}", item.seen),
                      ])
    });

    let border_type = match app.active_widget {
        Widget::Corpus => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        Widget::Corpus => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Corpus ({} file(s))", app.corpus_widget.files.len());
    let title = Span::styled(
        title,
        title_style
    );

    let table = Table::new(rows)
        .header(
            Row::new(vec!["File", "Instructions", "Unique"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
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
        Widget::Coverage => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        Widget::Coverage => Style::default().add_modifier(Modifier::BOLD),
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
                      ])
    });

    let border_type = match app.active_widget {
        Widget::Crash => BorderType::Thick,
        _ => BorderType::Plain
    };

    let title_style = match app.active_widget {
        Widget::Crash => Style::default().add_modifier(Modifier::BOLD),
        _ => Style::default()
    };

    let title = format!("Crashes ({} file(s))", app.crashes_widget.files.len());

    let title = Span::styled(
        title,
        title_style
    );

    let table = Table::new(rows)
        .header(
            Row::new(vec!["File", "Instructions", "Unique"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(1),
        )
        .block(Block::default().title(title).borders(Borders::ALL).border_type(border_type))
        .highlight_style(selected_style)
        .widths(&[
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
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