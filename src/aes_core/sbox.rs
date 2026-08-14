use super::gf256::inv;

/// Effectue une rotation circulaire d'un bit vers la gauche sur un octet.
pub fn rotl(value: u8) -> u8 {
    if value & 0x80 != 0 {
        (value << 1) | 0x01
    } else {
        value << 1
    }
}

/// Transformation affine de la S-box AES : XOR de `value` avec ses
/// 4 rotations successives, puis XOR avec la constante 0x63.
pub fn affine_transform(value: u8) -> u8 {
    let r1 = rotl(value);
    let r2 = rotl(r1);
    let r3 = rotl(r2);
    let r4 = rotl(r3);

    value ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63
}

/// Calcule la valeur de la S-box pour un octet, par inversion GF(2^8)
/// suivie de la transformation affine.
pub fn sbox(value: u8) -> u8 {
    affine_transform(inv(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_core::constants::SBOX;

    /// Vérifie que `sbox()` recalcule exactement la table `SBOX` codée
    /// en dur pour les 256 valeurs possibles.
    ///
    /// Cette comparaison exhaustive valide à la fois la construction
    /// mathématique de la S-box et la table définie dans `constants.rs`.
    #[test]
    fn test_sbox() {
        for i in 0..256 {
            assert_eq!(sbox(i as u8), SBOX[i]);
        }
    }
}
