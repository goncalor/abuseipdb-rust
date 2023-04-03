use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short)]
    conf_file: std::path::PathBuf,
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

    // let conf: Table = conf.parse().unwrap();
    let conf: Config = toml::from_str(&conf).unwrap();
    println!("{:?}", conf);

    let api_key = &conf.api_key;
    println!("{}", api_key);

    let body: String = ureq::get(
        "http://api.abuseipdb.com/api/v2/check-block?network=127.0.0.1/28&maxAgeInDays=15",
    )
    .set("Key", api_key)
    .call()?
    .into_string()?;

    println!("{}", body);
    Ok(())
}
