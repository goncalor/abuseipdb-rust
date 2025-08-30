use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{self, BufRead, Write};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(short, default_value = "conf.toml")]
    conf_file: std::path::PathBuf,

    #[command(subcommand)]
    command: Commands,

    #[arg(help = "File to write output to. If unspecified, output goes to stdout")]
    output_file: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
// #[command(flatten_help = true)]
enum Commands {
    /// Get data about IPs
    Check {
        ips_file: std::path::PathBuf,

        #[arg(long, default_value_t = 30)]
        max_age: u16,

        #[arg(short, default_value_t = false, help = "Verbose (includes reports)")]
        verbose: bool,
    },
    /// Get data about CIDR blocks
    CheckBlock {
        subnets_file: std::path::PathBuf,

        #[arg(long, default_value_t = 30)]
        max_age: u16,
    },
    /// Get blacklist data
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
            value_parser = clap::builder::PossibleValuesParser::new(["4", "6"]),
            help = "Include only specified IP version in the report"
        )]
        ip_version: Option<String>,
    },
    /// Write a configuration file with the provided API key
    Configure {},
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    data: serde_json::Value,
}

fn main() -> Result<(), ureq::Error> {
    let args = Cli::parse();
    // dbg!(&args);

    if let Commands::Configure {} = args.command {
        configure(&args.conf_file)?;
        std::process::exit(0);
    }

    let conf = std::fs::read_to_string(&args.conf_file).expect(&format!(
        "Could not read config file '{0}'",
        args.conf_file.display()
    ));
    let conf: Config = toml::from_str(&conf).unwrap();
    let api_key = &conf.api_key;

    let mut output: Box<dyn Write> = match args.output_file {
        Some(f) => Box::new(
            File::create_new(&f).expect(&format!("Could not create file '{0}'", f.display())),
        ),
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
        Commands::Blacklist {
            min_confidence,
            limit,
            plain,
            ip_version,
        } => blacklist(
            &api_key,
            min_confidence,
            limit,
            plain,
            ip_version,
            &mut output,
        )?,
        Commands::Configure {} => unreachable!(),
        // _ => todo!(),
    };

    Ok(())
}

fn check_block(
    subnet: &String,
    api_key: &String,
    max_age: u16,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let query = ureq::get("https://api.abuseipdb.com/api/v2/check-block")
        .query("network", subnet)
        .query("maxAgeInDays", max_age.to_string());
    let response: Response = query
        .header("Key", api_key)
        .call()?
        .body_mut()
        .read_json::<Response>()?;

    let addresses = response
        .data
        .get("reportedAddress")
        .expect("missing reportedAddress")
        .as_array()
        .expect("expected reportedAddress to be an array");
    for address in addresses {
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
    let mut query = ureq::get("https://api.abuseipdb.com/api/v2/check")
        .query("ipAddress", ip)
        .query("maxAgeInDays", max_age.to_string());
    if verbose {
        query = query.query("verbose", "");
    }

    let response: Response = query
        .header("Key", api_key)
        .call()?
        .body_mut()
        .read_json::<Response>()?;

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

fn blacklist(
    api_key: &String,
    min_confidence: u8,
    limit: u32,
    plain: bool,
    ip_version: Option<String>,
    output: &mut Box<dyn Write>,
) -> Result<(), ureq::Error> {
    let mut query = ureq::get("https://api.abuseipdb.com/api/v2/blacklist")
        .query("confidenceMinimum", min_confidence.to_string())
        .query("limit", limit.to_string());
    if plain {
        query = query.query("plaintext", "");
    }
    if let Some(ver) = ip_version {
        query = query.query("ipVersion", ver);
    }

    let mut response = query.header("Key", api_key).call()?;

    if plain {
        writeln!(output, "{}", response.body_mut().read_to_string()?)?;
    } else {
        for address in response
            .body_mut()
            .read_json::<Response>()?
            .data
            .as_array()
            .expect("expected data to be an array")
        {
            writeln!(output, "{}", address)?;
        }
    }

    Ok(())
}

fn configure(conf_file: &std::path::PathBuf) -> Result<(), ureq::Error> {
    println!("Config will be written to '{0}'.", &conf_file.display());

    let mut buf = String::new();
    print!("API key: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut buf)?;
    let key = buf.trim().to_string();
    let conf = toml::to_string(&Config { api_key: key }).unwrap();

    // Error out if file exists
    let mut file = File::create_new(&conf_file)
        .expect(&format!("Could not create file '{0}'", conf_file.display()));
    write!(file, "{}", &conf)?;

    Ok(())
}
