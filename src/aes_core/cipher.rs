use super::key_expansion::key_expansion;
use super::state::State;

/// Assemble la clé de round numéro `round` à partir des 44 mots
/// générés par key_expansion, en un State prêt pour add_round_key.
fn round_key(round_keys: &[[u8; 4]; 44], round: usize) -> State {
    let w0 = round_keys[4 * round];
    let w1 = round_keys[4 * round + 1];
    let w2 = round_keys[4 * round + 2];
    let w3 = round_keys[4 * round + 3];

    let bytes: [u8; 16] = [
        w0[0], w0[1], w0[2], w0[3], w1[0], w1[1], w1[2], w1[3], w2[0], w2[1], w2[2], w2[3], w3[0],
        w3[1], w3[2], w3[3],
    ];

    State::from_bytes(bytes)
}

/// Chiffre un bloc de 16 octets avec AES-128.
///
/// Applique un AddRoundKey initial, 9 rounds complets (SubBytes,
/// ShiftRows, MixColumns, AddRoundKey), puis un round final sans
/// MixColumns, conformément à FIPS-197.
pub fn encrypt(plaintext: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let round_keys = key_expansion(key);
    let mut state = State::from_bytes(plaintext);

    state.add_round_key(&round_key(&round_keys, 0));

    for round in 1..10 {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_key(&round_keys, round));
    }

    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_key(&round_keys, 10));

    state.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie encrypt avec le vecteur de test officiel FIPS-197
    /// (Appendix B) : preuve que l'implémentation complète est
    /// conforme à la norme AES-128.
    #[test]
    fn test_nist_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let result = encrypt(plaintext, key);

        assert_eq!(result, expected);
    }
}
