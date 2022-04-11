#![feature(restricted_std)]
pub enum Command {
    // TOTP

    GetHOTP,



    GenKey,


    Prepare,



    //storage

    FindMatch,
    Report,

    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            // TOTP

            0 => Command::GetHOTP,

            // ECDH

            1 => Command::GenKey,
            // Digest

            // authentication encryption
            2 => Command::Prepare,

            // storage

            3 => Command::FindMatch,
            4 => Command::Report,
            _ => Command::Unknown,
        }
    }
}

pub enum Mode {
    Encrypt,
    Decrypt,
    Unknown,
}

impl From<u32> for Mode {
    #[inline]
    fn from(value: u32) -> Mode {
        match value {
            0 => Mode::Encrypt,
            1 => Mode::Decrypt,
            _ => Mode::Unknown,
        }
    }
}

// pub enum Status {
//     Failed,
//     Passed,
//     Unknown,
// }
//
// impl From<u32> for Status {
//     #[inline]
//     fn from(value: u32) -> Status {
//         match value {
//             0 => Status::Failed,
//             1 => Status::Passed,
//             _ => Status::Unknown,
//         }
//     }
// }
pub enum StorageMode {
    DerivedKeys,
    UserData,
    Unknown,
}

impl From<u32> for StorageMode {
    #[inline]
    fn from(value: u32) -> StorageMode {
        match value {
            0 => StorageMode::DerivedKeys,
            1 => StorageMode::UserData,
            _ => StorageMode::Unknown,
        }
    }
}
// Key size 20 bytes
pub const KEY_SIZE: usize = 256;
pub const K_LEN: usize = 32;
pub const BUFFER_SIZE: usize = 30;
pub const AAD_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));
