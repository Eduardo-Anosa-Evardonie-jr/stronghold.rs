// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use futures::future::RemoteHandle;

use std::{collections::HashMap, time::Duration};

use engine::vault::RecordHint;

use crate::{
    actors::{InternalActor, Procedure},
    client::{Client, ClientMsg},
    line_error,
    snapshot::Snapshot,
    utils::ask,
    utils::{index_of_unchecked, StatusMessage, StrongholdFlags},
    ClientId, Provider,
};

pub struct Stronghold {
    // actor system.
    system: ActorSystem,
    // clients in the system.
    client_ids: Vec<ClientId>,

    actors: Vec<ActorRef<ClientMsg>>,

    // client id and keydata
    data: HashMap<ClientId, Vec<u8>>,
    // current index of the client.
    current_target: usize,
}

impl Stronghold {
    /// Initializes a new instance of the system.  Sets up the first client actor.
    pub fn init_stronghold_system(
        system: ActorSystem,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> Self {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let client_ids = vec![client_id];
        let mut data: HashMap<ClientId, Vec<u8>> = HashMap::new();

        data.insert(client_id, keydata);

        let client = system
            .actor_of_args::<Client, _>(&id_str, client_id)
            .expect(line_error!());

        system
            .actor_of::<InternalActor<Provider>>(&format!("internal-{}", id_str))
            .expect(line_error!());

        system.actor_of::<Snapshot>("snapshot").expect(line_error!());

        let actors = vec![client];

        Self {
            system,
            client_ids,
            actors,
            data,
            current_target: 0,
        }
    }

    /// Starts actor model and sets current_target actor.  Can be used to add another stronghold actor to the system if called a 2nd time.
    pub fn spawn_stronghold_actor(
        &mut self,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        options: Vec<StrongholdFlags>,
    ) -> StatusMessage {
        let client_id = ClientId::load_from_path(&keydata, &client_path).expect(line_error!());
        let id_str: String = client_id.into();
        let counter = self.actors.len();

        if self.client_ids.contains(&client_id) {
            self.current_target = index_of_unchecked(&self.client_ids, &client_id);
        } else {
            let client = self
                .system
                .actor_of_args::<Client, _>(&id_str, client_id)
                .expect(line_error!());
            self.system
                .actor_of::<InternalActor<Provider>>(&format!("interal-{}", id_str))
                .expect(line_error!());

            self.actors.push(client);
            self.client_ids.push(client_id);
            self.data.insert(client_id, keydata);

            self.current_target = counter + 1;
        }

        StatusMessage::Ok
    }

    pub async fn write_data(
        &self,
        data: Vec<u8>,
        vault_path: Vec<u8>,
        record_counter: Option<usize>,
        hint: RecordHint,
    ) -> StatusMessage {
        let idx = self.current_target;

        let client = &self.actors[idx];

        // ask for write_data

        StatusMessage::Ok
    }

    pub async fn read_data(
        &self,
        vault_path: Vec<u8>,
        record_counter: Option<usize>,
    ) -> (Option<Vec<u8>>, StatusMessage) {
        unimplemented!()
    }

    pub async fn delete_data(&self, vault_path: Vec<u8>, record_counter: usize, should_gc: bool) -> StatusMessage {
        unimplemented!()
    }

    pub async fn garbage_collect(&self, vault_path: Vec<u8>, record_counter: usize) -> StatusMessage {
        unimplemented!()
    }

    pub async fn kill_stronghold(&self, client_path: Vec<u8>, kill_actor: bool, write_snapshot: bool) -> StatusMessage {
        unimplemented!()
    }

    pub async fn list_hints_and_ids(&self, vault_path: Vec<u8>) -> (Vec<(Vec<u8>, RecordHint)>, StatusMessage) {
        unimplemented!()
    }

    pub async fn runtime_exec(&self, control_request: Procedure) -> StatusMessage {
        unimplemented!()
    }

    pub async fn read_snapshot(
        &self,
        keydata: Vec<u8>,
        client_path: Vec<u8>,
        new_stronghold: bool,
        options: Option<Vec<StrongholdFlags>>,
    ) -> StatusMessage {
        unimplemented!()
    }

    pub async fn write_snapshot(&self, client_path: Vec<u8>, duration: Option<Duration>) -> StatusMessage {
        unimplemented!()
    }

    fn check_config_flags() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use riker::actors::*;

    use super::*;

    // use crate::client::{Client, SHRequest};

    // use futures::executor::block_on;

    #[test]
    fn test_stronghold() {
        let sys = ActorSystem::new().unwrap();

        let mut stronghold = Stronghold::init_stronghold_system(sys, b"test".to_vec(), b"test".to_vec(), vec![]);

        stronghold.spawn_stronghold_actor(b"another".to_vec(), b"test".to_vec(), vec![]);

        stronghold.system.print_tree()
    }
}