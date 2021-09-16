
pub enum Command {
    // TOTP
    RegisterSharedKey,
    GetHOTP,
    Test,
    //Dh key generation
    GenerateKey,
    DeriveKey,


    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::RegisterSharedKey,
            1 => Command::GetHOTP,
            2 => Command::Test,
            3 => Command::GenerateKey,
            4 => Command::DeriveKey,
            _ => Command::Unknown,
        }
    }
}

// Key size 20 bytes
pub const KEY_SIZE: usize = 256;

pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
