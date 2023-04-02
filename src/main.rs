fn main() -> Result<(), ureq::Error> {
    let body: String = ureq::get("http://api.abuseipdb.com/api/v2/check-block?network=127.0.0.1/28&maxAgeInDays=15")
        .set("Key", "")
        .call()?
        .into_string()?;

    println!("{}", body);
    Ok(())
}
