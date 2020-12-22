

use std::error::Error;
use std::io::{stdout, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use tui::{
    backend::{CrosstermBackend},
    Terminal
};


mod ui;

use widget::*;

fn main() -> Result<(), Box<dyn Error>> {
    // Terminal initialization

    let is_debug = false;
    let mut stdout_val = stdout();
    execute!(stdout_val, EnterAlternateScreen, EnableMouseCapture)?;
    enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout_val);

    let mut terminal = Terminal::new(backend)?;

    // Setup input handling
    let (tx, rx) = mpsc::channel();

    let tick_rate = Duration::from_millis(250);
    thread::spawn(move || {
        let mut last_tick = Instant::now();
        loop {
            // poll for tick rate duration, if no events, sent tick event.
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            if event::poll(timeout).unwrap() {
                if let Event::Key(key) = event::read().unwrap() {
                    tx.send(TuiEvent::Input(key)).unwrap();
                }
            }
            if last_tick.elapsed() >= tick_rate {
                tx.send(TuiEvent::Tick).unwrap();
                last_tick = Instant::now();
            }
        }
    });

    let mut app = App::new("Rewind monitor");

    terminal.clear()?;
    terminal.hide_cursor()?;

     loop {
        terminal.draw(|f| draw(f, &mut app))?;
        match rx.recv()? {
            TuiEvent::Input(event) => match event.code {
                KeyCode::Char('q') => {
                    cleanup_terminal(&mut terminal)?;
                    break;
                }
                KeyCode::Char(c) => app.on_key(c),
                // KeyCode::Left => app.on_left(),
                // KeyCode::Right => app.on_right(),
                KeyCode::Tab => app.on_tab(),
                KeyCode::Up => app.on_up(),
                KeyCode::Down => app.on_down(),
                _ => {}
            },
            TuiEvent::Tick => {
                app.on_tick();
            }
        }
        if app.should_quit {
            break;
        }
    }

    Ok(())
}
