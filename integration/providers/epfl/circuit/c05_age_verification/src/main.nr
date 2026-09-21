use eid::constants;

fn main(
    // Private input
    credential_string: str<constants::CREDENTIAL_LEN>,
    // Public input
    current_date: pub u64,
) {
    // Calculate the age in seconds
    let mut birth_timestamp: u64 = 0;
    for i in 0..constants::CREDENTIAL_LEN_DOB {
        birth_timestamp = birth_timestamp * 10
            + credential_string.as_bytes()[i + constants::CREDENTIAL_POS_DOB] as u64
            - 48;
    }
    assert(birth_timestamp <= current_date);
    let age_seconds = current_date - birth_timestamp;

    // Ignoring leap years and check against 18 years of duration: 365.25 * 24 * 3600 = 31,557,600
    let seconds_per_year = 31557600;
    let min_age_seconds = 18 * seconds_per_year;
    assert(age_seconds >= min_age_seconds);
}
