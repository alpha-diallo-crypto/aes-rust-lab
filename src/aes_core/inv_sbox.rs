use super::gf256::inv;
use super::sbox::rotl;

/// Inverse de la transformation affine de la S-box.
pub fn inv_affine_transform(value: u8) -> u8 {
    let r1 = rotl(value);
    let r3 = rotl(rotl(r1));
    let r6 = rotl(rotl(rotl(r3)));
    r1 ^ r3 ^ r6 ^ 0x05
}

/// Calcule la valeur inverse de la S-box pour un octet.
/// Utilisée pour InvSubBytes lors du déchiffrement.
pub fn inv_sbox(value: u8) -> u8 {
    inv(inv_affine_transform(value))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_core::constants::INV_SBOX;

    /// Vérifie que `inv_sbox()` recalcule exactement la table `INV_SBOX` codée
    /// en dur pour les 256 valeurs possibles.
    ///
    /// Cette comparaison exhaustive valide à la fois la construction
    /// mathématique de la S-box et la table définie dans `constants.rs`.
    #[test]
    fn test_inv_sbox() {
        for i in 0..256 {
            assert_eq!(inv_sbox(i as u8), INV_SBOX[i]);
        }
    }
}