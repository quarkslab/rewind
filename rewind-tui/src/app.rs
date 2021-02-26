
use std::path::PathBuf;
use std::collections::HashMap;

use rewind_core::fuzz::Stats;

use crate::widget::{ActiveWidget, CorpusFile, CorpusWidget, CoverageWidget, CrashesWidget, Function, InstanceWidget, LogsWidget, StatsWidget};
pub (crate) struct App {
    pub stats_widget: StatsWidget,
    pub instances_widget: InstanceWidget,
    pub corpus_widget: CorpusWidget,
    pub coverage_widget: CoverageWidget,
    pub crashes_widget: CrashesWidget,
    pub logs_widget: LogsWidget,
    pub active_widget: ActiveWidget,
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
            active_widget: ActiveWidget::Instances,
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
        let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
        let horodated_log = format!("{} {}", now.to_rfc2822(), log);
        self.logs_widget.items.push(horodated_log);
        if self.logs_widget.items.len() > 10 {
            self.logs_widget.items.remove(0);
        }
        self.logs_widget.next();
    }

    pub fn on_total_coverage(&mut self, coverage: usize) {
        self.stats_widget.coverage = coverage as u64;
    }

    pub fn on_tick(&mut self) {

    }

    pub fn on_tab(&mut self) {
        let widget = self.active_widget.next();
        self.active_widget = widget;

    }

    pub fn on_up(&mut self) {
        match self.active_widget {
            ActiveWidget::Instances => {
                self.instances_widget.previous()
            },
            ActiveWidget::Corpus => {
                self.corpus_widget.previous()
            },
            ActiveWidget::Coverage => {
                self.coverage_widget.previous()
            },
            ActiveWidget::Crash => {
                self.crashes_widget.previous()
            }
        }

    }

    pub fn on_page_up(&mut self) {
        match self.active_widget {
            ActiveWidget::Instances => {
                self.instances_widget.previous()
            },
            ActiveWidget::Corpus => {
                self.corpus_widget.previous()
            },
            ActiveWidget::Coverage => {
                self.coverage_widget.previous()
            },
            ActiveWidget::Crash => {
                self.crashes_widget.previous()
            }
        }

    }

    pub fn on_down(&mut self) {
        match self.active_widget {
            ActiveWidget::Instances => {
                self.instances_widget.next()
            },
            ActiveWidget::Corpus => {
                self.corpus_widget.next()
            },
            ActiveWidget::Coverage => {
                self.coverage_widget.next()
            },
            ActiveWidget::Crash => {
                self.crashes_widget.next()
            }
        }
    }

    pub fn on_page_down(&mut self) {
        match self.active_widget {
            ActiveWidget::Instances => {
                self.instances_widget.next()
            },
            ActiveWidget::Corpus => {
                self.corpus_widget.next()
            },
            ActiveWidget::Coverage => {
                self.coverage_widget.next()
            },
            ActiveWidget::Crash => {
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