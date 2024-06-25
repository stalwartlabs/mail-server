/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    PublicKey,
};
use sha2::Sha256;
use store::rand::Rng;

/*

 From https://github.com/mozilla/rust-ece (MPL-2.0 license)
 Adapted to use 'aes-gcm' and 'p256' crates instead of 'openssl'.

*/

const ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX: &str = "WebPush: info\0";
const ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH: usize = 144;
const ECE_WEBPUSH_IKM_LENGTH: usize = 32;
const ECE_WEBPUSH_PUBLIC_KEY_LENGTH: usize = 65;
const ECE_WEBPUSH_DEFAULT_RS: u32 = 4096;
const ECE_WEBPUSH_DEFAULT_PADDING_BLOCK_SIZE: usize = 128;

const ECE_AES128GCM_PAD_SIZE: usize = 1;
const ECE_AES128GCM_KEY_INFO: &str = "Content-Encoding: aes128gcm\0";
const ECE_AES128GCM_NONCE_INFO: &str = "Content-Encoding: nonce\0";
const ECE_AES128GCM_HEADER_LENGTH: usize = 21;
const ECE_AES_KEY_LENGTH: usize = 16;

const ECE_NONCE_LENGTH: usize = 12;
const ECE_TAG_LENGTH: usize = 16;

pub fn ece_encrypt(
    p256dh: &[u8],
    client_auth_secret: &[u8],
    mut data: &[u8],
) -> Result<Vec<u8>, String> {
    let salt = store::rand::thread_rng().gen::<[u8; 16]>();
    let server_secret = EphemeralSecret::random(&mut OsRng);
    let server_public_key = server_secret.public_key();
    let server_public_key_bytes = server_public_key.to_encoded_point(false);

    let client_public_key = PublicKey::from_sec1_bytes(p256dh).map_err(|e| e.to_string())?;
    let shared_secret = server_secret.diffie_hellman(&client_public_key);

    let ikm_info = generate_info(p256dh, server_public_key_bytes.as_bytes());
    let ikm = hkdf_sha256(
        client_auth_secret,
        &shared_secret.raw_secret_bytes()[..],
        &ikm_info,
        ECE_WEBPUSH_IKM_LENGTH,
    )?;
    let key = hkdf_sha256(
        &salt,
        &ikm,
        ECE_AES128GCM_KEY_INFO.as_bytes(),
        ECE_AES_KEY_LENGTH,
    )?;
    let nonce = hkdf_sha256(
        &salt,
        &ikm,
        ECE_AES128GCM_NONCE_INFO.as_bytes(),
        ECE_NONCE_LENGTH,
    )?;

    // Calculate pad length
    let mut pad_length = ECE_WEBPUSH_DEFAULT_PADDING_BLOCK_SIZE
        - (data.len() % ECE_WEBPUSH_DEFAULT_PADDING_BLOCK_SIZE);
    if pad_length < ECE_AES128GCM_PAD_SIZE {
        pad_length += ECE_WEBPUSH_DEFAULT_PADDING_BLOCK_SIZE;
    }

    // Split into records
    let rs = ECE_WEBPUSH_DEFAULT_RS as usize - ECE_TAG_LENGTH;
    let mut min_num_records = data.len() / (rs - 1);
    if data.len() % (rs - 1) != 0 {
        min_num_records += 1;
    }
    let mut pad_length = std::cmp::max(pad_length, min_num_records);
    let total_size = data.len() + pad_length;
    let mut num_records = total_size / rs;
    let size_of_final_record = total_size % rs;
    if size_of_final_record > 0 {
        num_records += 1;
    }
    let data_per_record = data.len() / num_records;
    let mut extra_data = data.len() % num_records;
    if size_of_final_record > 0 && data_per_record > size_of_final_record - 1 {
        extra_data += data_per_record - (size_of_final_record - 1)
    }
    let mut sequence_number = 0;
    let mut plain_text =
        Vec::with_capacity(data_per_record + ECE_WEBPUSH_DEFAULT_PADDING_BLOCK_SIZE);

    // Write header
    let key_id = server_public_key_bytes.as_bytes();
    debug_assert_eq!(key_id.len(), ECE_WEBPUSH_PUBLIC_KEY_LENGTH);
    let mut output = Vec::with_capacity(
        ECE_AES128GCM_HEADER_LENGTH + key_id.len() + total_size + num_records * ECE_TAG_LENGTH,
    );
    output.extend_from_slice(&salt);
    output.extend_from_slice(&ECE_WEBPUSH_DEFAULT_RS.to_be_bytes());
    output.push(key_id.len() as u8);
    output.extend_from_slice(key_id);

    loop {
        let records_remaining = num_records - sequence_number;
        if records_remaining == 0 {
            break;
        }
        let mut data_share = data_per_record;
        if data_share > data.len() {
            data_share = data.len();
        } else if extra_data > 0 {
            let mut extra_share = extra_data / (records_remaining - 1);
            if extra_data % (records_remaining - 1) != 0 {
                extra_share += 1;
            }
            data_share += extra_share;
            extra_data -= extra_share;
        }

        let cur_data = &data[0..data_share];
        data = &data[data_share..];
        let padding = std::cmp::min(pad_length, rs - data_share);
        pad_length -= padding;
        let cur_sequence_number = sequence_number;
        sequence_number += 1;

        let padded_plaintext_len = cur_data.len() + padding;

        plain_text.extend_from_slice(cur_data);
        plain_text.push(if sequence_number == num_records { 2 } else { 1 });
        plain_text.resize(padded_plaintext_len, 0);

        output.extend_from_slice(&aes_gcm_128_encrypt(
            &key,
            &generate_iv(&nonce, cur_sequence_number),
            &plain_text,
        )?);
        plain_text.clear();
    }

    Ok(output)
}

fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, String> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), secret);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|e| e.to_string())?;
    Ok(okm)
}

fn aes_gcm_128_encrypt(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    <Aes128Gcm as aes_gcm::KeyInit>::new(&GenericArray::clone_from_slice(key))
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| e.to_string())
}

fn generate_info(
    client_public_key: &[u8],
    server_public_key: &[u8],
) -> [u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH] {
    let mut info = [0u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH];
    let prefix = ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX.as_bytes();
    let mut offset = prefix.len();
    info[0..offset].copy_from_slice(prefix);
    info[offset..offset + ECE_WEBPUSH_PUBLIC_KEY_LENGTH].copy_from_slice(client_public_key);
    offset += ECE_WEBPUSH_PUBLIC_KEY_LENGTH;
    info[offset..].copy_from_slice(server_public_key);
    info
}

pub fn generate_iv(nonce: &[u8], counter: usize) -> [u8; ECE_NONCE_LENGTH] {
    let mut iv = [0u8; ECE_NONCE_LENGTH];
    let offset = ECE_NONCE_LENGTH - 8;
    iv[0..offset].copy_from_slice(&nonce[0..offset]);
    let mask = u64::from_be_bytes((&nonce[offset..]).try_into().unwrap());
    iv[offset..].copy_from_slice(&(mask ^ (counter as u64)).to_be_bytes());
    iv
}
