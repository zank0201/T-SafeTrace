
pub enum Command {
    // TOTP
    RegisterSharedKey,
    GetHOTP,
    Test,
    // RSA key generation
    GenKey,
    GetSize,
    Encrypt,
    Decrypt,
    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::RegisterSharedKey,
            1 => Command::GetHOTP,
            2 => Command::Test,
            3 => Command::GenKey,
            4 => Command::GetSize,
            5 => Command::Encrypt,
            6 => Command::Decrypt,
            _ => Command::Unknown,
        }
    }
}


pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
