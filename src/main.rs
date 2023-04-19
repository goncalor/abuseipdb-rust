use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs::File;
use std::io::{self, BufRead, Write};
use ureq::serde_json;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(short)]
    conf_file: std::path::PathBuf,

    #[command(subcommand)]
    command: Commands,

    subnets_file: std::path::PathBuf,

    output_file: Option<std::path::PathBuf>,

    #[arg(long, default_value_t = 15)]
    max_age: u16,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Check { ips_file: std::path::PathBuf },
    CheckBlock { subnets_file: std::path::PathBuf },
    Blacklist {},
}

#[derive(Deserialize, Debug)]
struct Config {
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    data: serde_json::Value,
}

fn main() -> Result<(), ureq::Error> {
    let args = Cli::parse();
    dbg!(&args);

    let conf = std::fs::read_to_string(args.conf_file)?;
    let conf: Config = toml::from_str(&conf).unwrap();
    let api_key = &conf.api_key;

    let mut output: Box<dyn Write> = match args.output_file {
        Some(f) => Box::new(File::create(f)?),
        None => Box::new(std::io::stdout()),
    };

    let subnets_file = File::open(args.subnets_file).unwrap();
    for subnet in io::BufReader::new(subnets_file).lines() {
        let subnet = subnet?;
        let response: Response = ureq::get(&format!(
            "https://api.abuseipdb.com/api/v2/check-block?network={subnet}&maxAgeInDays={0}",
            args.max_age
        ))
        .set("Key", api_key)
        .call()?
        .into_json()?;

        for address in response
            .data
            .get("reportedAddress")
            .expect("missing reportedAddress")
            .as_array()
            .expect("expected reportedAddress to be an array")
        {
            writeln!(output, "{}", address)?;
        }
    }

    Ok(())
}
