#[macro_use]
extern crate log;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Command {
    Generate(GenerateOptions),
    Pubkey(PubkeyOptions),
}

#[derive(Debug, StructOpt)]
/// Generate a keypair.
struct GenerateOptions {
    #[structopt(short = "f", long)]
    /// Overwrite if keypair already exists
    overwrite: bool,
    #[structopt(name = "PATH", default_value = "/etc/bacchus/keypair", parse(from_os_str))]
    /// Directory to write keypair into
    path: PathBuf,
}

#[derive(Debug, StructOpt)]
/// Print base64 encoded public key.
struct PubkeyOptions {
    #[structopt(name = "PATH", default_value = "/etc/bacchus/keypair", parse(from_os_str))]
    /// Directory to read public key from
    path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("getrandom error: {0}")]
    Getrandom(#[from] #[source] getrandom::Error),
    #[error("Failed to open keypair: {0}")]
    Keypair(#[source] std::io::Error),
    #[error("I/O error: {0}")]
    Io(#[from] #[source] std::io::Error),
}

fn generate(options: GenerateOptions) -> Result<(), Error> {
    let GenerateOptions { overwrite, path } = options;

    info!("Generating keypair");
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;

    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];
    tweetnacl::sign_keypair_seed(&mut pk, &mut sk, &seed);

    info!("Writing keypair to {}", path.to_string_lossy());

    let mut open_options = OpenOptions::new();
    open_options
        .write(true)
        .create(true)
        .truncate(true)
        .create_new(!overwrite);

    let secret_key_path = path.join("tweetnacl");
    let public_key_path = path.join("tweetnacl.pub");

    std::fs::create_dir_all(path).map_err(Error::Keypair)?;

    let mut secret_key = open_options.open(secret_key_path).map_err(Error::Keypair)?;
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o600);
    secret_key.set_permissions(perms)?;
    secret_key.sync_all()?;
    secret_key.write_all(&sk)?;
    secret_key.flush()?;
    drop(secret_key);

    let mut public_key = open_options.open(public_key_path).map_err(Error::Keypair)?;
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o644);
    public_key.set_permissions(perms)?;
    public_key.sync_all()?;
    public_key.write_all(&pk)?;
    public_key.flush()?;
    drop(public_key);

    Ok(())
}

fn pubkey(options: PubkeyOptions) -> Result<(), Error> {
    let PubkeyOptions { path } = options;

    let public_key_path = path.join("tweetnacl.pub");
    info!("Opening public key {}", public_key_path.to_string_lossy());

    let mut pk = [0u8; 32];
    let mut public_key = File::open(public_key_path).map_err(Error::Keypair)?;
    public_key.read_exact(&mut pk)?;
    println!("{}", base64::encode(&pk));

    Ok(())
}

fn main() {
    env_logger::init();

    let command = Command::from_args();
    let result = match command {
        Command::Generate(opts) => generate(opts),
        Command::Pubkey(opts) => pubkey(opts),
    };

    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }
}
