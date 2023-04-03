use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::io::{self, BufRead};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short)]
    conf_file: std::path::PathBuf,

    subnets_file: std::path::PathBuf,
}

#[derive(Deserialize, Debug)]
struct Config {
    api_key: String,
}

fn main() -> Result<(), ureq::Error> {
    let args = Cli::parse();
    println!("{:?}", args);

    let conf = match std::fs::read_to_string(args.conf_file) {
        Ok(f) => f,
        Err(e) => panic!("{}", e),
    };

    let conf: Config = toml::from_str(&conf).unwrap();
    println!("{:?}", conf);

    let api_key = &conf.api_key;
    println!("{}", api_key);

    let subnets_file = File::open(args.subnets_file).unwrap();
    for subnet in io::BufReader::new(subnets_file).lines() {
        let subnet = subnet?;
        println!("{}", subnet);

        let body: String = ureq::get(&format!(
            "http://api.abuseipdb.com/api/v2/check-block?network={subnet}&maxAgeInDays=15"
        ))
        .set("Key", api_key)
        .call()?
        .into_string()?;

        println!("{}", body);
    }

    Ok(())
}
