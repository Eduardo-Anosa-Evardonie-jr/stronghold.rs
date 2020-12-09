// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
#[allow(non_snake_case, dead_code)]
mod hd;
mod ids;
mod types;

pub use self::{
    ask::ask,
    ids::{ClientId, LoadFromPath, VaultId},
    types::{StatusMessage, StrongholdFlags},
};

pub fn index_of_unchecked<T>(slice: &[T], item: &T) -> usize {
    if ::std::mem::size_of::<T>() == 0 {
        return 0;
    }
    (item as *const _ as usize - slice.as_ptr() as usize) / std::mem::size_of::<T>()
}
