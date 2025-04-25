use alloc::vec::Vec;
use wavv::{Wav, Data};
use crate::constants::devices::TEST_WAV;
use crate::filesys::ext2::filesystem::{Ext2, FilesystemError};
use crate::serial_println;

use super::dma::DmaBuffer;
use super::hda::AudioData;



pub async fn read_wav(fs: &Ext2, path: &str) -> Result<Wav, FilesystemError> {
    let wav_bytes = fs.read_file(path).await?;
    match Wav::from_bytes(&wav_bytes) {
        Ok(wav) => Ok(wav),
        Err(_) => Err(FilesystemError::InvalidFd)
    }
}

pub async fn write_wav(fs: &Ext2, path: &str, wav: &Wav) -> Result<(), FilesystemError> {
    let bytes = wav.to_bytes();
    fs.write_file(path, &bytes).await.map(|_| ())
}

/// Call this from hda.rs to load and re-save a WAV file
pub async fn load_wav(/*fs: &Ext2*/) -> Result<AudioData, FilesystemError> {
    let input_path = "kernel/src/devices/audio/new_romantics_swift.wav";

    // match read_wav(fs, input_path).await {
    match Wav::from_bytes(&TEST_WAV) {
        Ok(wav) => {
            crate::debug!("WAV loaded: {} ch, {} bit, {} Hz", wav.fmt.num_channels, wav.fmt.bit_depth, wav.fmt.sample_rate);

            match &wav.data {
                Data::BitDepth8(samples) => crate::debug!("8-bit samples: {}", samples.len()),
                Data::BitDepth16(samples) => crate::debug!("16-bit samples: {}", samples.len()),
                Data::BitDepth24(samples) => crate::debug!("24-bit samples: {}", samples.len()),
            }

            Ok(AudioData {
                bytes: wav.to_bytes(),
                fmt: get_fmt(&wav)
            })
        }
        Err(e) => {
            crate::debug!("Failed to read WAV file {}: {:?}", input_path, e);
            Err(FilesystemError::InvalidPath)
        }
    }
}

pub fn get_fmt(wav: &Wav) -> u16 {
    let samples = match &wav.data {
        Data::BitDepth8(_) => 0,
        Data::BitDepth16(_) => 1,
        Data::BitDepth24(_) => 3,
    };

    let channels = wav.fmt.num_channels - 1;
    let sample_base = if wav.fmt.sample_rate == 44_100 { 1 } else { 0 };

    let multiplier = match wav.fmt.sample_rate {
        96_000 | 88_200 | 32_000 => 0b001,
        144_000 => 0b010,
        192_000 | 176_400 => 0b011,
        _ => 0b000,
    };

    let divider = match wav.fmt.sample_rate {
        24_000 | 22_050 => 0b001,
        16_000 | 24_000 => 0b010,
        11_025 => 0b011,
        9_600 => 0b100,
        8_000 => 0b101,
        6_857 => 0b110,
        6_000 => 0b111,
        _ => 0b000,
    };

    crate::debug!("sample_rate    = {:#X}", wav.fmt.sample_rate);
    crate::debug!("num_channels   = {:#X}", wav.fmt.num_channels);
    crate::debug!("bit_depth      = {:#X}", wav.fmt.bit_depth);
    crate::debug!("sample_base    = {:#X}", sample_base);
    crate::debug!("multiplier     = {:#X}", multiplier);
    crate::debug!("divider        = {:#X}", divider);
    crate::debug!("samples        = {:#X}", samples);
    crate::debug!("channels       = {:#X}", channels);

    let fmt: u16 = ((sample_base as u16) << 14) 
                 | ((multiplier as u16) << 11) 
                 | ((divider as u16) << 8) 
                 | ((samples as u16) << 4) 
                 | channels;

    crate::debug!("FMT: {:#X}", fmt);

    fmt
}
