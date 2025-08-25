use clap::{Parser, Subcommand};
use serde::Deserialize;
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
    /// (Unimplemented)
    Configure {},
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
    // dbg!(&args);

    let conf = match std::fs::read_to_string(&args.conf_file) {
        Ok(c) => c,
        Err(e) => panic!(
            "Could not read config file '{0}': {1}",
            args.conf_file.display(),
            e
        ),
    };
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
        Commands::Configure {} => configure(&args.conf_file)?,
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
    let response: Response = ureq::get(&format!(
        "https://api.abuseipdb.com/api/v2/check-block?network={subnet}&maxAgeInDays={0}",
        max_age
    ))
    .header("Key", api_key)
    .call()?
    .body_mut()
    .read_json::<Response>()?;

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
    //TODO: use .query()
    let mut response = ureq::get(&format!(
        "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={min_confidence}&limit={limit}{0}{1}",
        match plain {
            true => "&plaintext",
            false => "",
        },
        match ip_version {
            Some(ver) => format!("&ipVersion={ver}"),
            None => String::new(),
        },
    ))
    .header("Key", api_key)
    .call()?;

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

    dbg!(key);

    Ok(())
}
