use toml::Table;

fn main() -> Result<(), ureq::Error> {
    let conf_path = std::path::Path::new("conf.toml");
    let conf = match std::fs::read_to_string(conf_path) {
        Ok(f) => f,
        Err(e) => panic!("{}", e),
    };

    let conf: Table = conf.parse().unwrap();
    println!("{}", conf);

    let api_key = conf["api_key"].as_str().unwrap();
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
