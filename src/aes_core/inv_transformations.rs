use super::constants::INV_SBOX;
use super::gf256::mul;
use super::state::State;

impl State {
    /// InvShiftRows : inverse de ShiftRows. Décale circulairement
    /// chaque ligne de la matrice vers la droite (au lieu de la
    /// gauche), du même nombre de positions que son numéro de ligne.
    pub fn inv_shift_rows(&mut self) {
        for row in 0..4 {
            let original_row = self.bytes[row];
            for col in 0..4 {
                let source_col = (col + 4 - row) % 4;
                self.bytes[row][col] = original_row[source_col];
            }
        }
    }

    /// InvSubBytes : inverse de SubBytes. Chaque octet de la matrice
    /// est remplacé par sa valeur correspondante dans INV_SBOX,
    /// retrouvant ainsi l'octet présent avant SubBytes.
    pub fn inv_sub_bytes(&mut self) {
        for row in 0..4 {
            for col in 0..4 {
                let byte = self.bytes[row][col];
                self.bytes[row][col] = INV_SBOX[byte as usize];
            }
        }
    }

    /// InvMixColumns : inverse de MixColumns. Chaque colonne est
    /// multipliée dans GF(2^8) par la matrice inverse (coefficients
    /// 14, 11, 13, 9), retrouvant la colonne présente avant MixColumns.
    pub fn inv_mix_columns(&mut self) {
        for col in 0..4 {
            let a0 = self.bytes[0][col];
            let a1 = self.bytes[1][col];
            let a2 = self.bytes[2][col];
            let a3 = self.bytes[3][col];

            self.bytes[0][col] = mul(14, a0) ^ mul(11, a1) ^ mul(13, a2) ^ mul(9, a3);
            self.bytes[1][col] = mul(9, a0) ^ mul(14, a1) ^ mul(11, a2) ^ mul(13, a3);
            self.bytes[2][col] = mul(13, a0) ^ mul(9, a1) ^ mul(14, a2) ^ mul(11, a3);
            self.bytes[3][col] = mul(11, a0) ^ mul(13, a1) ^ mul(9, a2) ^ mul(14, a3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que InvShiftRows annule ShiftRows.
    #[test]
    fn test_inv_shift_rows_cancels_shift_rows() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state = State::from_bytes(input);

        state.shift_rows();
        state.inv_shift_rows();

        assert_eq!(state.to_bytes(), input);
    }

    /// Vérifie que InvSubBytes annule SubBytes.
    #[test]
    fn test_inv_sub_bytes_cancels_sub_bytes() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state = State::from_bytes(input);

        state.sub_bytes();
        state.inv_sub_bytes();

        assert_eq!(state.to_bytes(), input);
    }

    /// Vérifie que InvMixColumns annule MixColumns.
    #[test]
    fn test_inv_mix_columns_cancels_mix_columns() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut state = State::from_bytes(input);

        state.mix_columns();
        state.inv_mix_columns();

        assert_eq!(state.to_bytes(), input);
    }
}