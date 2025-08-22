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

    output_file: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Check {
        ips_file: std::path::PathBuf,

        #[arg(long, default_value_t = 30)]
        max_age: u16,

        #[arg(short, default_value_t = false, help = "Verbose (includes reports)")]
        verbose: bool,
    },
    CheckBlock {
        subnets_file: std::path::PathBuf,

        #[arg(long, default_value_t = 30)]
        max_age: u16,
    },
    Blacklist {
        #[arg(
            name = "cmin",
            value_name = "CMIN",
            long,
            default_value_t = 100,
            help = "Mininum confidence score"
        )]
        min_confidence: u8,

        #[arg(
            long,
            default_value_t = 10_000,
            help = "The maximum number of IPs included in the report"
        )]
        limit: u32,

        #[arg(
            long,
            default_value_t = false,
            help = "Output plaintext, one IP per line. The default output format is JSON"
        )]
        plain: bool,

        #[arg(
            long,
            default_value = "4,6",
            value_parser = clap::builder::PossibleValuesParser::new(["4", "6", "4,6"]),
            help = "IP versions to include in the report"
        )]
        ip_version: String,
    },
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
        // TODO: error if file exists?
        Some(f) => Box::new(File::create(f)?),
        None => Box::new(std::io::stdout()),
    };

    match args.command {
        Commands::CheckBlock {
            subnets_file,
            max_age,
        } => check_block_file(&subnets_file, &api_key, max_age, &mut output)?,
        Commands::Check {
            ips_file,
            max_age,
            verbose,
        } => check_ip_file(&ips_file, &api_key, max_age, verbose, &mut output)?,
        _ => todo!(),
    };

    Ok(())
}

fn check_block(
    subnet: &String,
    api_key: &String,
    max_age: u16,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let response: Response = ureq::get(&format!(
        "https://api.abuseipdb.com/api/v2/check-block?network={subnet}&maxAgeInDays={0}",
        max_age
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

    Ok(())
}

fn check_block_file(
    subnets_file: &std::path::PathBuf,
    api_key: &String,
    max_age: u16,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let subnets_file = File::open(subnets_file).unwrap();
    for subnet in io::BufReader::new(subnets_file).lines() {
        check_block(&subnet?, api_key, max_age, output)?
    }

    Ok(())
}

fn check_ip(
    ip: &String,
    api_key: &String,
    max_age: u16,
    verbose: bool,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let response: Response = ureq::get(&format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={0}{1}",
        max_age,
        match verbose {
            true => "&verbose",
            false => "",
        },
    ))
    .set("Key", api_key)
    .call()?
    .into_json()?;

    writeln!(output, "{}", response.data)?;

    Ok(())
}

fn check_ip_file(
    ips_file: &std::path::PathBuf,
    api_key: &String,
    max_age: u16,
    verbose: bool,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let ips_file = File::open(ips_file).unwrap();
    for ip in io::BufReader::new(ips_file).lines() {
        let ip = ip?;
        check_ip(&ip, api_key, max_age, verbose, output)?
    }

    Ok(())
}
