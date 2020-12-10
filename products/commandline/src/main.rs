// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

fn init_stronghold(matches: &ArgMatches) -> Option <(Stronghold, Vec<u8>)> {
    if let Some(pass) = matches.value_of("password") {
        if let Some(vault) = matches.value_of("vault") {
            let sys = ActorSystem::new().unwrap();
            let password = pass.as_bytes().to_vec();
            let stronghold = Stronghold::init_stronghold_system(sys, password, CLIENT.to_vec(), vec![]);
            let vault_path = vault.as_bytes().to_vec();
            return Some((stronghold, vault_path));
        }
    }
    None
}

// handle the encryption command.
fn encrypt_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            if let Some(plain) = matches.value_of("plain") {
                let hint = matches.value_of("hint").unwrap_or("").as_bytes().to_vec();
                futures::executor::block_on(stronghold.write_data(
                    plain.as_bytes().to_vec(),
                    vault_path,
                    None,
                    RecordHint::new(hint).expect(line_error!()),
                ));
                futures::executor::block_on(stronghold.write_snapshot(CLIENT.to_vec(), None));
            };
        };
    }
}

// handle the list command.
fn list_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("list") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            let (list, _) = futures::executor::block_on(stronghold.list_hints_and_ids(vault_path));
            for (id, hint) in list {
                println!("Id: {}, Hint: {:?}", id, hint);
            }
        }
    }
}

// handle the read command.
fn read_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("read") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            if let Some(ref id) = matches.value_of("id") {
                let id = str::parse::<usize>(id).expect(line_error!());
                futures::executor::block_on(stronghold.read_data(vault_path, Some(id)));
            }
        }
    }
}

// create a record with a revoke transaction.  Data isn't actually deleted until it is garbage collected.
fn revoke_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("revoke") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            if let Some(ref id) = matches.value_of("id") {
                let id = str::parse::<usize>(id).expect(line_error!());
                futures::executor::block_on(stronghold.delete_data(vault_path, id, false));
                futures::executor::block_on(stronghold.write_snapshot(CLIENT.to_vec(), None));
            }
        }
    }
}

// garbage collect the chain.  Remove any revoked data from the chain.
fn garbage_collect_vault_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("garbage_collect") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            futures::executor::block_on(stronghold.garbage_collect(vault_path));
        }
    }
}

// Purge a record from the chain: revoke and garbage collect.
fn purge_command(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("purge") {
        if let Some((stronghold, vault_path)) = init_stronghold(&matches) {
            if let Some(ref id) = matches.value_of("id") {
                let id = str::parse::<usize>(id).expect(line_error!());
                futures::executor::block_on(stronghold.delete_data(vault_path, id, true));
                futures::executor::block_on(stronghold.write_snapshot(CLIENT.to_vec(), None));
            }
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();

    encrypt_command(&matches);
    read_command(&matches);
    list_command(&matches);
    revoke_command(&matches);
    garbage_collect_vault_command(&matches);
    purge_command(&matches);
}
