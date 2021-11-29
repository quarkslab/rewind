
use std::{collections::BTreeMap, io::Read};

use clap::Clap;
use colored::Colorize;

use color_eyre::{Report, eyre::WrapErr};
use rewind_core::mutation::Mutator;

use crate::helpers;

/// Manage snapshots.
#[derive(Clap, Debug)]
pub(crate) struct Mutation {
    #[clap(subcommand)]
    subcmd: MutationSubCommand
}

impl Mutation {

    pub(crate) fn run(&self) -> Result<(), Report> {
        match &self.subcmd {
            MutationSubCommand::Apply(t) => t.run(),
            MutationSubCommand::View(t) => t.run(),
        }
    }
}

#[derive(Clap, Debug)]
enum MutationSubCommand {
    Apply(MutationApply),
    View(MutationView),
}

/// Apply mutations to input
#[derive(Clap, Debug)]
struct MutationApply {
    /// Inputs description
    #[clap(parse(from_os_str))]
    pub inputs: std::path::PathBuf,

    /// Inputs data
    #[clap(parse(from_os_str))]
    pub data: Option<std::path::PathBuf>,

}

impl MutationApply {
    fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Apply mutations");
        progress.single("Loading inputs description");
        let input_desc = rewind_core::mutation::InputDesc::load(&self.inputs)
            .wrap_err(format!("Can't load input description {}", self.inputs.display()))?;

        // let items = &input_desc.items;

        let colors = ["red", "blue", "green", "yellow", "magenta", "cyan"];
        let mut buffer = if let Some(path) = self.data.as_ref() {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            buffer.resize(0x1000, 0);
            buffer
        } else {
            vec![0u8; 0x1000]
        };

        for item in input_desc.items { 
            let mut colors_iter = colors.iter().cycle();
            progress.single(format!("viewing {}", item.name));

            let slice = &mut buffer[item.offset..item.offset + item.size];

            let mut mutator = Mutator::from(&item.fields)?;

            mutator.mutate(slice);

            let mut map = BTreeMap::new();
            for field in mutator.fields.iter() {
                let color = *colors_iter.next().unwrap();
                map.insert(field.name(),color);
            }

            for (index, bytes) in slice.chunks(0x10).enumerate() {
                print!("{:08x}: ", index * 0x10);
                for (byte_index, byte) in bytes.iter().enumerate() {
                    let offset = index * 0x10 + byte_index;
                    let formatted_byte = format!("{:02x}", *byte);
                    if let Some(span) = mutator.fields.iter().find(|&s| { 
                        offset >= s.offset()  && offset < s.offset() + s.size()
                    }) {
                        let color = *map.get(span.name()).unwrap();
                        print!("{} ", formatted_byte.color(color));
                    } else {
                        print!("{} ", formatted_byte);
                    }
                }

                for (byte_index, byte) in bytes.iter().enumerate() {
                    let offset = index * 0x10 + byte_index;
                    let formatted_byte = if byte.is_ascii_graphic() {
                        format!("{}", *byte as char)
                    } else {
                        ".".to_string()
                    };

                    if let Some(span) = mutator.fields.iter().find(|&s| { 
                        offset >= s.offset()  && offset < s.offset() + s.size()
                    }) {
                        let color = *map.get(span.name()).unwrap();
                        print!("{}", formatted_byte.color(color));
                    } else {
                        print!("{}", formatted_byte);
                    }
                }

                println!();
            }

            println!();

            for field in mutator.fields.iter() {
                let color = *map.get(field.name()).unwrap();
                println!("{:<10}: {:08x}-{:08x}", field.name().color(color), field.offset(), field.offset() + field.size());
            }

            println!();

        }


        Ok(())
    }


}
/// View how bytes are mutated
#[derive(Clap, Debug)]
struct MutationView {
    /// Inputs description
    #[clap(parse(from_os_str))]
    pub inputs: std::path::PathBuf,

    /// Inputs data
    #[clap(parse(from_os_str))]
    pub data: Option<std::path::PathBuf>,
    
}

impl MutationView {

    fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("View mutations");

        progress.single("Loading inputs description");
        let input_desc = rewind_core::mutation::InputDesc::load(&self.inputs)
            .wrap_err(format!("Can't load input description {}", self.inputs.display()))?;

        // let items = &input_desc.items;

        let colors = ["red", "blue", "green", "yellow", "magenta", "cyan"];
        let buffer = if let Some(path) = self.data.as_ref() {
            let mut file = std::fs::File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            buffer.resize(0x1000, 0);
            buffer
        } else {
            vec![0u8; 0x1000]
        };

        for item in input_desc.items { 
            let mut colors_iter = colors.iter().cycle();
            progress.single(format!("viewing {}", item.name));

            let slice = &buffer[item.offset..item.offset + item.size];

            // let buffer = if let Some(path) = self.data.as_ref() {
            //     let mut file = std::fs::File::open(path)?;
            //     let mut buffer = Vec::new();
            //     file.read_to_end(&mut buffer)?;
            //     buffer
            // } else {
            //     vec![0u8; item.size]
            // };

            let mutator = Mutator::from(&item.fields)?;
            let mut map = BTreeMap::new();
            for field in mutator.fields.iter() {
                let color = *colors_iter.next().unwrap();
                map.insert(field.name(),color);
            }

            for (index, bytes) in slice.chunks(0x10).enumerate() {
                print!("{:08x}: ", index * 0x10);
                for (byte_index, byte) in bytes.iter().enumerate() {
                    let offset = index * 0x10 + byte_index;
                    let formatted_byte = format!("{:02x}", *byte);
                    if let Some(span) = mutator.fields.iter().find(|&s| { 
                        offset >= s.offset()  && offset < s.offset() + s.size()
                    }) {
                        let color = *map.get(span.name()).unwrap();
                        print!("{} ", formatted_byte.color(color));
                    } else {
                        print!("{} ", formatted_byte);
                    }
                }

                for (byte_index, byte) in bytes.iter().enumerate() {
                    let offset = index * 0x10 + byte_index;
                    let formatted_byte = if byte.is_ascii_graphic() {
                        format!("{}", *byte as char)
                    } else {
                        ".".to_string()
                    };

                    if let Some(span) = mutator.fields.iter().find(|&s| { 
                        offset >= s.offset()  && offset < s.offset() + s.size()
                    }) {
                        let color = *map.get(span.name()).unwrap();
                        print!("{}", formatted_byte.color(color));
                    } else {
                        print!("{}", formatted_byte);
                    }
                }

                println!();
            }

            println!();

            for field in mutator.fields.iter() {
                let color = *map.get(field.name()).unwrap();
                println!("{:<10}: {:08x}-{:08x}", field.name().color(color), field.offset(), field.offset() + field.size());
            }

            println!();

        }

        Ok(())
    }

}