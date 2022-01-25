extern crate wasm_bindgen;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use std::iter::FromIterator;
use wasm_bindgen::prelude::*;

struct PasswordElement {
    symbol_count: u8,
    number_count: u8,
    upper_case_count: u8,
    lower_case_count: u8,
    character_type_count: u8,
    symbol_chars_array: Vec<char>,
    number_chars_array: Vec<char>,
    upper_case_chars_array: Vec<char>,
    lower_case_chars_array: Vec<char>,
}

#[wasm_bindgen]
pub fn generate(
    tag: &str,
    pwd: &str,
    version: u8,
    length: u8,
    has_symbol: bool,
    has_number: bool,
    has_lower_case: bool,
    has_upper_case: bool,
    avoid_ambiguity_char: bool,
) -> String {
    return generate_impl(
        tag,
        pwd,
        version,
        length,
        has_symbol,
        has_number,
        has_lower_case,
        has_upper_case,
        avoid_ambiguity_char,
    );
}

fn generate_impl(
    tag: &str,
    pwd: &str,
    version: u8,
    length: u8,
    has_symbol: bool,
    has_number: bool,
    has_lower_case: bool,
    has_upper_case: bool,
    avoid_ambiguity_char: bool,
) -> String {
    let tag_hash = Sha512::digest(tag.as_bytes());
    let pwd_hash = Sha512::digest(pwd.as_bytes());
    let version_hash = Sha512::digest(version.to_string().as_bytes());

    type HmacSha512 = Hmac<Sha512>;
    let mut hmac = HmacSha512::new_from_slice(format!("{:x}", pwd_hash).as_bytes()).unwrap();
    hmac.update(format!("{:x}{:x}", tag_hash, version_hash).as_bytes());
    let hmac_result = format!("{:x}", hmac.finalize().into_bytes());

    let start_index = hmac_result.chars().next().unwrap().to_digit(16).unwrap();
    let end_index = length as u32 + start_index;
    let seed = &hmac_result[start_index as usize..end_index as usize];
    let seed: Vec<u32> = seed.chars().flat_map(|c| c.to_digit(16)).collect();

    let mut password_element = PasswordElement {
        symbol_count: 0,
        number_count: 0,
        upper_case_count: 0,
        lower_case_count: 0,
        character_type_count: 3,
        symbol_chars_array: if avoid_ambiguity_char {
            "@#$%^&*+-"
        } else {
            "!@#$%^&*+-"
        }
        .chars()
        .collect(),
        number_chars_array: if avoid_ambiguity_char {
            "23456789"
        } else {
            "0123456789"
        }
        .chars()
        .collect(),
        upper_case_chars_array: if avoid_ambiguity_char {
            "ABDEFGHJLMNQRTY"
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        }
        .chars()
        .collect(),
        lower_case_chars_array: if avoid_ambiguity_char {
            "abdefghjmnqrty"
        } else {
            "abcdefghijklmnopqrstuvwxyz"
        }
        .chars()
        .collect(),
    };

    password_element.character_type_count =
        has_symbol as u8 + has_number as u8 + has_upper_case as u8 + has_lower_case as u8;

    if has_symbol {
        password_element.symbol_count = length / password_element.character_type_count;
    }

    if has_number {
        password_element.number_count = if !(has_upper_case || has_lower_case) {
            length - password_element.symbol_count
        } else {
            length / password_element.character_type_count
        }
    }

    if has_upper_case {
        password_element.upper_case_count = if !has_lower_case {
            length - password_element.symbol_count - password_element.number_count
        } else {
            (length - password_element.symbol_count - password_element.number_count) / 2
        }
    }
    if has_lower_case {
        password_element.lower_case_count = length
            - password_element.symbol_count
            - password_element.number_count
            - password_element.upper_case_count;
    }

    let mut password_chars = vec![0 as char; length as usize];

    for (index, value) in seed.iter().enumerate() {
        let mut cursor = 0;
        let mut i = 0;
        let value = *value as i32;
        while i <= value {
            if password_chars[cursor] != 0 as char {
                i -= 1;
            }
            if i != value {
                cursor = if cursor == length as usize - 1 {
                    0
                } else {
                    cursor + 1
                };
            }
            i += 1;
        }

        let symbol_count = password_element.symbol_count as usize;
        let number_count = password_element.number_count as usize;
        let upper_case_count = password_element.upper_case_count as usize;
        let chars_index = value as usize;

        password_chars[cursor] = if index < symbol_count {
            get_element_char(&password_element.symbol_chars_array, chars_index)
        } else if index < symbol_count + number_count {
            get_element_char(&password_element.number_chars_array, chars_index)
        } else if index < symbol_count + number_count + upper_case_count {
            get_element_char(&password_element.upper_case_chars_array, chars_index)
        } else {
            get_element_char(&password_element.lower_case_chars_array, chars_index)
        }
    }

    String::from_iter(password_chars)
}

fn get_element_char(chars: &Vec<char>, index: usize) -> char {
    if index < chars.len() {
        chars[index]
    } else {
        chars[index % chars.len()]
    }
}
