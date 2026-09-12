use super::cipher::round_key;
use super::key_expansion::key_expansion;
use super::state::State;

/// Déchiffre un bloc AES-128 de 16 octets avec une clé de 16 octets.
/// Applique les transformations inverses dans l'ordre des clés de
/// ronde, de la dernière clé jusqu'à la clé initiale.
pub fn decrypt(ciphertext: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let round_keys = key_expansion(key);
    let mut state = State::from_bytes(ciphertext);

    // Ajoute la dernière clé de ronde avant les transformations inverses.
    state.add_round_key(&round_key(&round_keys, 10));

    // Effectue les neuf rondes inverses, de la ronde 9 à la ronde 1.
    for round in (1..10).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_key(&round_keys, round));
        state.inv_mix_columns();
    }

    // Effectue la dernière ronde inverse sans InvMixColumns.
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_key(&round_keys, 0));

    state.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cipher::encrypt;

    /// Vérifie que le déchiffrement annule le chiffrement.
    #[test]
    fn test_decrypt_cancels_encrypt() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];

        let ciphertext = encrypt(plaintext, key);
        let decrypted = decrypt(ciphertext, key);

        assert_eq!(decrypted, plaintext);
    }
}