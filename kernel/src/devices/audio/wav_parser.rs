use wavv::{Wav, Data};
use crate::filesys::ext2::filesystem::{Ext2, FilesystemError};
use crate::serial_println;

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
pub async fn run_wav(fs: &Ext2) {
    let input_path = "kernel/src/devices/audio/new_romantics_swift.wav";
    let output_path = "kernel/src/devices/audio/new_romantics.wav";

    match read_wav(fs, input_path).await {
        Ok(wav) => {
            serial_println!("WAV loaded: {} ch, {} bit, {} Hz", wav.fmt.num_channels, wav.fmt.bit_depth, wav.fmt.sample_rate);

            match &wav.data {
                Data::BitDepth8(samples) => serial_println!("8-bit samples: {}", samples.len()),
                Data::BitDepth16(samples) => serial_println!("16-bit samples: {}", samples.len()),
                Data::BitDepth24(samples) => serial_println!("24-bit samples: {}", samples.len()),
            }

            match write_wav(fs, output_path, &wav).await {
                Ok(_) => serial_println!("WAV written to {}", output_path),
                Err(e) => serial_println!("Failed to write WAV: {:?}", e),
            }
        }
        Err(e) => {
            serial_println!("Failed to read WAV file {}: {:?}", input_path, e);
        }
    }
}
