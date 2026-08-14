use super::constants::SBOX;
use super::gf256::{add, mul};
use super::state::State;

impl State {
    /// ShiftRows : décale circulairement chaque ligne de la matrice
    /// vers la gauche, d'un nombre de positions égal à son numéro
    /// de ligne (la ligne 0 ne bouge pas, la ligne 3 décale de 3).
    ///
    /// Cette opération répartit les octets entre les différentes
    /// colonnes, complétant la diffusion apportée par MixColumns.
    pub fn shift_rows(&mut self) {
        for row in 0..4 {
            let original_row = self.bytes[row];
            for col in 0..4 {
                let source_col = (col + row) % 4;
                self.bytes[row][col] = original_row[source_col];
            }
        }
    }

    /// SubBytes : remplace chaque octet de la matrice par sa valeur
    /// correspondante dans la S-box.
    ///
    /// C'est la seule source de non-linéarité du chiffrement : sans
    /// cette étape, AES pourrait être décrit par de simples équations
    /// linéaires, ce qui le rendrait facilement cassable.
    pub fn sub_bytes(&mut self) {
        for row in 0..4 {
            for col in 0..4 {
                let byte = self.bytes[row][col];
                self.bytes[row][col] = SBOX[byte as usize];
            }
        }
    }

    /// MixColumns : mélange les 4 octets de chaque colonne entre eux,
    /// par une multiplication matricielle fixe dans GF(2^8).
    ///
    /// Combinée à ShiftRows, cette opération contribue à diffuser
    /// l'influence de chaque octet dans tout l'état, au fil des tours.
    pub fn mix_columns(&mut self) {
        for col in 0..4 {
            let a0 = self.bytes[0][col];
            let a1 = self.bytes[1][col];
            let a2 = self.bytes[2][col];
            let a3 = self.bytes[3][col];

            self.bytes[0][col] = mul(2, a0) ^ mul(3, a1) ^ a2 ^ a3;
            self.bytes[1][col] = a0 ^ mul(2, a1) ^ mul(3, a2) ^ a3;
            self.bytes[2][col] = a0 ^ a1 ^ mul(2, a2) ^ mul(3, a3);
            self.bytes[3][col] = mul(3, a0) ^ a1 ^ a2 ^ mul(2, a3);
        }
    }

    /// AddRoundKey : combine l'état avec une clé de round par XOR,
    /// case par case.
    ///
    /// C'est l'étape du tour où l'état est combiné avec la clé de
    /// round dérivée de la clé secrète. Le XOR étant sa propre
    /// inverse, cette opération est réversible sans nécessiter de
    /// variante séparée pour le déchiffrement.
    pub fn add_round_key(&mut self, round_key: &State) {
        for row in 0..4 {
            for col in 0..4 {
                let state_byte = self.bytes[row][col];
                let key_byte = round_key.bytes[row][col];
                self.bytes[row][col] = add(state_byte, key_byte);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que chaque ligne est bien décalée du bon nombre de
    /// positions (ligne 0 inchangée, ligne 3 décalée de 3).
    #[test]
    fn test_shift_rows() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state = State::from_bytes(input);
        state.shift_rows();
        assert_eq!(state.bytes[0], [0, 4, 8, 12]);
        assert_eq!(state.bytes[1], [5, 9, 13, 1]);
        assert_eq!(state.bytes[2], [10, 14, 2, 6]);
        assert_eq!(state.bytes[3], [15, 3, 7, 11]);
    }

    /// Vérifie la substitution sur deux octets connus (0x53 et 0).
    #[test]
    fn test_sub_bytes() {
        let input: [u8; 16] = [0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut state = State::from_bytes(input);
        state.sub_bytes();
        // 0x53 doit devenir SBOX[0x53] = 0xed
        assert_eq!(state.bytes[0][0], 0xed);
        // 0 doit devenir SBOX[0] = 0x63
        assert_eq!(state.bytes[1][0], 0x63);
    }

    /// Vérifie la première case de la première colonne après MixColumns,
    /// recalculée avec la formule officielle (mul(coefficient, valeur)).
    #[test]
    fn test_mix_columns() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state = State::from_bytes(input);
        state.mix_columns();
        assert_eq!(state.bytes[0][0], mul(2, 0) ^ mul(3, 1) ^ 2 ^ 3);
    }

    /// Vérifie MixColumns avec le vecteur de test officiel FIPS-197 :
    /// une colonne indépendante du reste de l'implémentation.
    #[test]
    fn test_mix_columns_fips_vector() {
        let input: [u8; 16] = [0xd4, 0xbf, 0x5d, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut state = State::from_bytes(input);
        state.mix_columns();
        assert_eq!(state.bytes[0][0], 0x04);
        assert_eq!(state.bytes[1][0], 0x66);
        assert_eq!(state.bytes[2][0], 0x81);
        assert_eq!(state.bytes[3][0], 0xe5);
    }

    /// Vérifie que AddRoundKey est bien sa propre inverse : appliquer
    /// deux fois la même clé redonne exactement l'état d'origine.
    #[test]
    fn test_add_round_key_is_its_own_inverse() {
        let input: [u8; 16] = [
            5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80,
        ];
        let key_bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut state = State::from_bytes(input);
        let key = State::from_bytes(key_bytes);
        state.add_round_key(&key);
        state.add_round_key(&key);
        assert_eq!(state.to_bytes(), input);
    }
}
