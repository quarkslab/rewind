// from https://github.com/jonhoo/rust-agenda

use std::fmt;
use std::io::prelude::*;
use std::num::ParseIntError;

use color_eyre::Report;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Progress {
    Section,
    Headline,
    Item,
    Bottom,
}

impl Progress {
    pub fn enter<D: fmt::Display>(self, name: D) -> Self {
        let mut t = term::stderr().unwrap();

        match self {
            Progress::Section => {
                t.fg(term::color::BLUE).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                write!(t, ":: ").unwrap();

                t.reset().unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "{}", name).unwrap();

                t.reset().unwrap();

                Progress::Headline
            }
            Progress::Headline => {
                t.fg(term::color::GREEN).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                write!(t, "==> ").unwrap();

                t.reset().unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "{}", name).unwrap();

                t.reset().unwrap();

                Progress::Item
            }
            Progress::Item | Progress::Bottom => {
                t.fg(term::color::BLUE).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                write!(t, "  -> ").unwrap();

                t.reset().unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "{}", name).unwrap();

                t.reset().unwrap();

                Progress::Bottom
            }
        }
    }

    pub fn leave(self) -> Progress {
        match self {
            Progress::Bottom => Progress::Item,
            Progress::Item => Progress::Headline,
            Progress::Headline | Progress::Section => {
                // empty line after section end
                let mut t = term::stderr().unwrap();
                writeln!(t).unwrap();

                Progress::Section
            }
        }
    }

    #[allow(dead_code)]
    pub fn root(mut self) -> Progress {
        loop {
            if let Progress::Section = self {
                break self;
            }
            self = self.leave()
        }
    }

    #[allow(dead_code)]
    pub fn error<D: fmt::Display>(&self, msg: D) {
        let mut t = term::stderr().unwrap();

        match self {
            Progress::Section => {
                t.fg(term::color::RED).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, ":: ERROR: {}", msg).unwrap();
                t.reset().unwrap();
            }
            Progress::Headline => {
                t.fg(term::color::RED).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                write!(t, "==> ERROR: ").unwrap();

                t.reset().unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "{}", msg).unwrap();

                t.reset().unwrap();
            }
            Progress::Item | Progress::Bottom => {
                t.fg(term::color::RED).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "  -> {}", msg).unwrap();
                t.reset().unwrap();
            }
        }
    }

    pub fn warn<D: fmt::Display>(&self, msg: D) {
        let mut t = term::stderr().unwrap();

        match self {
            Progress::Section => {
                t.fg(term::color::YELLOW).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, ":: WARN: {}", msg).unwrap();
                t.reset().unwrap();
            }
            Progress::Headline => {
                t.fg(term::color::YELLOW).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                write!(t, "==> WARN: ").unwrap();

                t.reset().unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "{}", msg).unwrap();

                t.reset().unwrap();
            }
            Progress::Item | Progress::Bottom => {
                t.fg(term::color::YELLOW).unwrap();
                t.attr(term::Attr::Bold).unwrap();
                writeln!(t, "  -> {}", msg).unwrap();
                t.reset().unwrap();
            }
        }
    }

    pub fn single<D: fmt::Display>(&self, name: D) {
        self.clone().enter(name).leave();
    }
}

pub fn start() -> Progress {
    Progress::Section
}

pub (crate) fn parse_hex(input: &str) -> Result<usize, ParseIntError> {
    usize::from_str_radix(input, 16)
}

pub (crate) fn decode_instruction(buffer: &[u8]) -> Result<zydis::DecodedInstruction, Report> {
    let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
    let result = decoder.decode(buffer)?;
    if let Some(instruction) = result {
        Ok(instruction)
    } else {
        Err(Report::msg("can't decode instruction".to_string()))
    }
}

pub (crate) fn format_instruction(rip: u64, instruction: zydis::DecodedInstruction) -> Result<String, Report> {
    let mut formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
    formatter.set_property(zydis::FormatterProperty::HexUppercase(false))?;
    let mut buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
    formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None)?;
    let output = format!("{}", buffer);
    Ok(output)
}

