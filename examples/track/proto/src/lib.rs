#![feature(restricted_std)]
pub enum Command {
    // TOTP
    RegisterSharedKey,
    GetHOTP,
    GenerateKey,
    DeriveKey,
    Sign,
    Verify,
    GenKey,
    Update,
    DoFinal,

    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::RegisterSharedKey,
            1 => Command::GetHOTP,
            2 => Command::GenerateKey,
            3 => Command::DeriveKey,
            4 => Command::Sign,
            5 => Command::Verify,
            6 => Command::GenKey,
            7 => Command::Update,
            8 => Command::DoFinal,
            _ => Command::Unknown,
        }
    }
}

// Key size 20 bytes
pub const KEY_SIZE: usize = 256;
pub const BUFFER_SIZE: usize = 16;
pub const AAD_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
