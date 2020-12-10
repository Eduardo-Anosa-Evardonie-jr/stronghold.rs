// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
// create a line error with the file and the line number

use iota_stronghold::{Stronghold, RecordHint};
use riker::actors::ActorSystem;
use clap::{load_yaml, App, ArgMatches};

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

const CLIENT: &[u8; 3] = b"CLI";

// handle the encryption command.
fn encrypt_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Some(vault) = matches.value_of("vault") {
                    let sys = ActorSystem::new().unwrap();
                    let vault_path = vault.as_bytes().to_vec();
                    let hint = matches.value_of("hint").unwrap_or("").as_bytes().to_vec();
                    let stronghold = Stronghold::init_stronghold_system(sys, pass.as_bytes().to_vec(), CLIENT.to_vec(), vec![]);
                    futures::executor::block_on(stronghold.create_new_vault(vault_path.clone()));
                    futures::executor::block_on(stronghold.write_data(
                        plain.as_bytes().to_vec(),
                        vault_path.clone(),
                        None,
                        RecordHint::new(hint).expect(line_error!()),
                    ));
                    futures::executor::block_on(stronghold.write_snapshot(CLIENT.to_vec(), None));
                }
            };
        };
    }
}

fn read_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some(pass) = matches.value_of("password") {
            if let Some(vault) = matches.value_of("vault") {
                if let Some(id) = matches.value_of("id") {
                    let sys = ActorSystem::new().unwrap();
                    let password = pass.as_bytes().to_vec();
                    let vault_path = vault.as_bytes().to_vec();
                    let stronghold = Stronghold::init_stronghold_system(sys, password.clone(), CLIENT.to_vec(), vec![]);
                    futures::executor::block_on(stronghold.read_snapshot(password, CLIENT.to_vec(), false, None));
                    futures::executor::block_on(stronghold.read_data(vault_path.clone(), Some(str::parse::<usize>(id).unwrap())));
                }
            };
        };
    }
}


fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    encrypt_command(&matches);
    read_command(&matches);
}
