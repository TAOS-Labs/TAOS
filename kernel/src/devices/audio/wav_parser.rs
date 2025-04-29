use wavv::{Wav, Data};
use crate::constants::devices::TEST_WAV;
use crate::devices::mmio::MMioConstPtr;
use crate::filesys::ext2::filesystem::{Ext2, FilesystemError};

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
    let input_path = "kernel/src/devices/audio/myfile.wav";

    // match read_wav(fs, input_path).await {
    match Wav::from_bytes(&TEST_WAV) {
        Ok(wav) => {
            crate::debug!("WAV loaded: {} ch, {} bit, {} Hz", wav.fmt.num_channels, wav.fmt.bit_depth, wav.fmt.sample_rate);

            let (samples, len) = match &wav.data {
                Data::BitDepth8(samples) => (samples.as_ptr(), samples.len()),
                Data::BitDepth16(samples) => (samples.as_ptr() as *const u8, samples.len() * 2),
                Data::BitDepth24(samples) => (samples.as_ptr() as *const u8, samples.len() * 4),
            };

            let fmt = get_fmt(&wav);

            Ok(AudioData {
                bytes: MMioConstPtr(samples),
                len: len,
                data: wav.data, // holding onto data to prevent deallocation of buffer
                fmt: fmt
            })
        }
        Err(e) => {
            crate::debug!("Failed to read WAV file {}: {:?}", input_path, e);
            Err(FilesystemError::InvalidPath)
        }
    }
}

pub fn get_fmt(wav: &Wav) -> u16 {
    let bit_depth: u8 = match wav.fmt.bit_depth {
        8 => 0,
        16 => 1,
        20 => 2,
        24 => 3,
        32 => 4,
        _ => 5
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
        16_000 => 0b010, // | 24_000?
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
    crate::debug!("samples        = {:#X}", bit_depth);
    crate::debug!("channels       = {:#X}", channels);

    let fmt: u16 = ((sample_base as u16) << 14) 
                 | ((multiplier as u16) << 11) 
                 | ((divider as u16) << 8) 
                 | ((bit_depth as u16) << 4) 
                 | channels;

    crate::debug!("FMT: {:#X}", fmt);

    fmt
}
