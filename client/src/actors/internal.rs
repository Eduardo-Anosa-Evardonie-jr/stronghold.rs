// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, RecordHint, RecordId};

use engine::snapshot;

use runtime::zone::soft;

use crate::{
    actors::{ProcResult, SMsg},
    bucket::Bucket,
    client::ClientMsg,
    internals::Provider,
    key_store::KeyStore,
    line_error,
    utils::{StatusMessage, VaultId},
    ClientId,
};

pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    client_id: ClientId,
    bucket: Bucket<P>,
    keystore: KeyStore<P>,
}

/// Messages used for the KeyStore Actor.
#[derive(Clone, Debug)]
pub enum InternalMsg {
    CreateVault(VaultId, RecordId),
    ReadData(VaultId, RecordId),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    InitRecord(VaultId, RecordId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),
    WriteSnapshot(snapshot::Key, Option<String>, Option<PathBuf>, String),
    ReadSnapshot(snapshot::Key, Option<String>, Option<PathBuf>, String),
    ReloadData(Vec<u8>, Vec<u8>, StatusMessage),
    ClearCache,
}

/// Messages used internally by the client.
#[derive(Clone, Debug)]
pub enum InternalResults {
    ReturnCreateVault(VaultId, RecordId, StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(VaultId, RecordId, StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(VaultId, Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache(Vec<VaultId>, Vec<Vec<RecordId>>, StatusMessage),
}

impl ActorFactoryArgs<ClientId> for InternalActor<Provider> {
    fn create_args(id: ClientId) -> Self {
        let bucket = Bucket::new();
        let keystore = KeyStore::new();

        Self {
            bucket,
            keystore,
            client_id: id,
        }
    }
}

impl Actor for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<InternalMsg> for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            InternalMsg::CreateVault(vid, rid) => {
                let key = self.keystore.create_key(vid);

                let (_, rid) = self.bucket.create_and_init_vault(key, rid);

                let cstr: String = self.client_id.into();

                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(vid, rid, StatusMessage::Ok)),
                    sender,
                );
            }
            InternalMsg::ReadData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    let plain = self.bucket.read_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(plain, StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(
                            vec![],
                            StatusMessage::Error("Vault does not exist.".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::WriteData(vid, rid, payload, hint) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.write_payload(key.clone(), rid, payload, hint);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Error(
                            "Vault doesn't exist".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::InitRecord(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let rid = self.bucket.init_record(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid, StatusMessage::Ok)),
                        sender,
                    );
                }
            }
            InternalMsg::RevokeData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.revoke_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::Error(
                            "Failed to revoke record, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::GarbageCollect(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.garbage_collect(key.clone());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::Error(
                            "Failed to garbage collect, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::ListIds(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.bucket.list_ids(key.clone());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(vid, ids, StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(
                            vid,
                            vec![],
                            StatusMessage::Error("Failed to get list, vault wasn't found".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::ReloadData(cache, keystore, status) => {
                let (_, rids) = self.bucket.repopulate_data(cache);

                let vids = self.keystore.rebuild_keystore(keystore);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids, status)),
                    sender,
                );
            }
            InternalMsg::WriteSnapshot(pass, name, path, client_str) => {
                let cache = self.bucket.offload_data();
                let store = self.keystore.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(
                    SMsg::WriteSnapshot(pass, name, path, (cache, store), client_str),
                    sender,
                );
            }
            InternalMsg::ReadSnapshot(pass, name, path, client_str) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path, client_str), sender);
            }
            InternalMsg::ClearCache => {
                self.bucket.clear_cache();
                self.keystore.clear_keys();
            }
        }
    }
}
