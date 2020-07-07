use std::{collections::HashMap, convert::TryInto};

pub fn serialize_map(map: &HashMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    map.iter().fold(Vec::new(), |mut acc, (k, v)| {
        acc.extend(&k.len().to_le_bytes());
        acc.extend(k.as_slice());
        acc.extend(&v.len().to_le_bytes());
        acc.extend(v.as_slice());
        acc
    })
}

pub fn deserialize_buffer(bytes: &Vec<u8>) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut map = HashMap::new();

    let mut left = &bytes[..];
    while left.len() > 0 {
        let k = read_buffer(&mut left);
        let v = read_buffer(&mut left);
        map.insert(k, v);
    }

    map
}

fn read_buffer(input: &mut &[u8]) -> Vec<u8> {
    let (len, rest) = input.split_at(std::mem::size_of::<usize>());
    let len = usize::from_le_bytes(len.try_into().unwrap());
    let (v, rest) = rest.split_at(len);
    *input = rest;
    v.to_vec()
}