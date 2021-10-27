#![feature(restricted_std)]
pub enum Command {

    Sign,
    Verify,
    GenKey,
    RandomK,
    Update,
    DoFinal,
    Unknown,
}
impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::Sign,
            1 => Command::Verify,
            2 => Command::GenKey,
            3 => Command::RandomK,
            4 => Command::Update,
            5 => Command::DoFinal,
            _ => Command::Unknown,
        }
    }
}


pub const BUFFER_SIZE: usize = 16;
pub const KEY_SIZE: usize = 256;
pub const AAD_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
