// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

mod utils;
use utils::provider::Provider;

mod fresh;

use vault::{DBView, Key, Result, RecordId, ReadResult, WriteRequest, PreparedRead, Kind};

use std::{
    iter::empty,
    collections::HashMap,
};

fn write_to_read(wr: &WriteRequest) -> ReadResult {
    ReadResult::new(wr.kind(), wr.id(), wr.data())
}

#[test]
fn test_empty() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v = DBView::load(k, empty::<ReadResult>())?;

    assert_eq!(v.all().len(), 0);
    assert_eq!(v.absolute_balance(), (0, 0));
    assert_eq!(v.chain_ctrs(), HashMap::new());
    assert_eq!(v.gc().len(), 0);

    Ok(())
}

#[test]
fn test_truncate() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    writes.push(v0.writer(id).truncate()?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.absolute_balance(), (1, 1));
    assert_eq!(v1.chain_ctrs(), vec![(id, 0u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::RecordIsEmpty);

    Ok(())
}

#[test]
fn test_read_non_existent_record() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v = DBView::load(k.clone(), empty::<ReadResult>())?;

    let id = RecordId::random::<Provider>()?;
    assert_eq!(v.reader().prepare_read(&id)?, PreparedRead::NoSuchRecord);

    Ok(())
}

#[test]
fn test_write_cache_hit() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let data = fresh::data();
    let hint = fresh::record_hint();
    writes.append(&mut w.write(&data, hint)?);

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.absolute_balance(), (2, 2));
    assert_eq!(v1.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    assert_eq!(v1.reader().prepare_read(&id)?, PreparedRead::CacheHit(data));

    Ok(())
}

#[test]
fn test_write_cache_miss() -> Result<()> {
    let k: Key<Provider> = Key::random()?;
    let v0 = DBView::load(k.clone(), empty::<ReadResult>())?;

    let mut writes = vec![];

    let id = RecordId::random::<Provider>()?;
    let mut w = v0.writer(id);
    writes.push(w.truncate()?);
    let data = fresh::data();
    let hint = fresh::record_hint();
    let blob = match w.write(&data, hint)?.as_slice() {
        [w0, w1] => {
            assert_eq!(w0.kind(), Kind::Transaction);
            writes.push(w0.clone());

            assert_eq!(w1.kind(), Kind::Blob);
            w1.data().to_vec()
        },
        ws => panic!("{} unexpected writes", ws.len()),
    };

    let v1 = DBView::load(k, writes.iter().map(write_to_read))?;

    assert_eq!(v1.all().len(), 1);
    assert_eq!(v1.absolute_balance(), (2, 2));
    assert_eq!(v1.chain_ctrs(), vec![(id, 1u64)].into_iter().collect());
    assert_eq!(v1.gc().len(), 0);

    let r = v1.reader();
    let res = match r.prepare_read(&id)? {
        PreparedRead::CacheMiss(req) => req.result(blob),
        x => panic!("unexpected value: {:?}", x),
    };

    assert_eq!(r.read(res)?, data);

    Ok(())
}

#[test]
#[ignore = "not yet implemented"]
fn test_rekove() -> Result<()> {
    unimplemented!()
}

#[test]
#[ignore = "not yet implemented"]
fn test_rekove_then_write() -> Result<()> {
    unimplemented!()
}

#[test]
#[ignore = "not yet implemented"]
fn test_ensure_authenticty_of_blob() -> Result<()> {
    unimplemented!()
}
