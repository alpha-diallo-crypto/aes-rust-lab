use crate::aes_core::cipher::encrypt;
use crate::aes_core::decrypt::decrypt;

/// Ajoute un padding PKCS#7 au plaintext.
///
/// La taille d'un bloc AES est de 16 octets.
/// On ajoute entre 1 et 16 octets afin que la taille finale
/// soit toujours un multiple de 16.
///
/// Chaque octet ajouté contient la valeur du nombre
/// total d'octets de padding.
fn pad(plaintext: &[u8]) -> Vec<u8> {
    let n = plaintext.len();
    let mut data = plaintext.to_vec();
    let pad = 16 - (n % 16);

    for _ in 0..pad {
        data.push(pad as u8)
    }

    data
}

/// Vérifie et retire un padding PKCS#7.
///
/// Le dernier octet indique la taille du padding.
/// Tous les octets correspondants doivent contenir
/// cette même valeur.
///
/// Une erreur est retournée si le padding est invalide.
fn inv_pad(ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.is_empty() {
        return Err("padding invalide : données vides");
    }
    if ciphertext.len()%16!=0{
        return  Err("padding invalide");
    }

    let n = ciphertext.len();
    let pad = ciphertext[n - 1] as usize;

    if pad == 0 || pad > 16 {
        return Err("padding invalide");
    }

    if pad > n {
        return Err("padding invalide");
    }

    for i in (n - pad)..n {
        if ciphertext[i] != pad as u8 {
            return Err("padding invalide");
        }
    }

    Ok(ciphertext[0..n - pad].to_vec())
}

/// Chiffre un message avec AES-128 en mode CBC.
///
/// Le plaintext est d'abord complété avec un padding PKCS#7.
///
/// Pour le premier bloc :
/// C1 = AES(P1 XOR IV).
///
/// Pour chaque bloc suivant :
/// Ci = AES(Pi XOR C(i-1)).
pub fn cbc_encrypt(plaintext: &[u8],iv: [u8; 16],key: [u8; 16]) -> Vec<u8> {
    let mut ciphertext: Vec<u8> = Vec::new();

    let l = pad(plaintext);
    let n = l.len();
    let k = n / 16;

    let bloc1 = &l[0..16];
    let mut new_data: [u8; 16] = [0u8; 16];

    for i in 0..16 {
        new_data[i] = bloc1[i] ^ iv[i];
    }

    new_data = encrypt(new_data, key);
    ciphertext.extend_from_slice(&new_data);

    for j in 2..=k {
        let bloc = &l[16 * (j - 1)..16 * j];

        for i in 0..16 {
            new_data[i] = bloc[i] ^ new_data[i];
        }

        new_data = encrypt(new_data, key);
        ciphertext.extend_from_slice(&new_data);
    }

    ciphertext
}

/// Déchiffre un message chiffré avec AES-128 en mode CBC.
///
/// Pour le premier bloc :
/// P1 = AES^(-1)(C1) XOR IV.
///
/// Pour chaque bloc suivant :
/// Pi = AES^(-1)(Ci) XOR C(i-1).
///
/// Le padding PKCS#7 est ensuite vérifié et retiré.
/// Une erreur est retournée si le ciphertext ou le padding
/// est invalide.
pub fn cbc_decrypt(ciphertext: &[u8],iv: [u8; 16],key: [u8; 16]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.is_empty() {
        return Err("ciphertext vide");
    }

    if ciphertext.len() % 16 != 0 {
        return Err("taille du ciphertext invalide");
    }

    let mut plaintext: Vec<u8> = Vec::new();
    let l = ciphertext.to_vec();

    let n = ciphertext.len();
    let k = n / 16;

    let mut bloc1 = [0u8;16];
    for i in 0..16{
        bloc1[i]=l[i]
    }
    let mut new_data: [u8; 16] = decrypt(bloc1, key);

    for i in 0..16 {
        new_data[i] = new_data[i] ^ iv[i];
    }

    plaintext.extend_from_slice(&new_data);

    for j in 1..k {
        let bloc0 = &l[16 * (j - 1)..16 * j];
        let mut bloc1 = [0u8;16];
        for i in 0..16{
            bloc1[i]=l[16*j+i];
        }

        new_data = decrypt(bloc1, key);

        for i in 0..16 {
            new_data[i] = new_data[i] ^ bloc0[i];
        }

        plaintext.extend_from_slice(&new_data);
    }

    inv_pad(&plaintext)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Vérifie que les quatre premiers blocs produits par CBC
    /// correspondent au vecteur officiel NIST AES-128-CBC.
    ///
    /// Le plaintext fait déjà 64 octets, donc PKCS#7 ajoute
    /// un cinquième bloc complet de padding.
    #[test]
    fn test_cbc_encrypt_nist_vector() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,

            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,

            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,

            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];

        let expected_first_4_blocks: [u8; 64] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
            0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,

            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
            0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,

            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
            0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,

            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];

        let ciphertext = cbc_encrypt(&plaintext, iv, key);

        assert_eq!(
            &ciphertext[0..64],
            &expected_first_4_blocks[..]
        );
    }

    /// Vérifie qu'un ciphertext sans padding PKCS#7 valide
    /// est rejeté lors du déchiffrement.
    #[test]
    fn test_cbc_decrypt_rejects_invalid_padding() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let ciphertext: [u8; 64] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
            0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,

            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
            0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,

            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
            0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,

            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];

        let result = cbc_decrypt(&ciphertext, iv, key);

        assert!(result.is_err());
    }

    /// Vérifie qu'un message chiffré puis déchiffré
    /// redonne exactement le plaintext d'origine.
    #[test]
    fn test_cbc_round_trip() {
        let key: [u8; 16] = [
            1, 2, 3, 4,
            5, 6, 7, 8,
            9, 10, 11, 12,
            13, 14, 15, 16,
        ];

        let iv: [u8; 16] = [0; 16];

        let plaintext =
            b"je suis etudiant a l'universite de rennes!";

        let ciphertext = cbc_encrypt(plaintext, iv, key);
        let decrypted = cbc_decrypt(&ciphertext, iv, key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Vérifie qu'un ciphertext dont la taille n'est pas
    /// un multiple de 16 octets est rejeté.
    #[test]
    fn test_cbc_decrypt_invalid_length() {
        let key: [u8; 16] = [0; 16];
        let iv: [u8; 16] = [0; 16];

        let ciphertext: [u8; 17] = [0; 17];

        let result = cbc_decrypt(&ciphertext, iv, key);

        assert!(result.is_err());
    }
    /// Vérifie que PKCS#7 ajoute un bloc complet de padding
    /// lorsque le plaintext est déjà un multiple de 16 octets.
    ///
    /// Comme le plaintext fait 64 octets, le ciphertext
    /// doit contenir 80 octets après l'ajout du padding.
    #[test]
    
    fn test_cbc_encrypt_nist_vector_with_padding() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,

            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,

            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,

            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];

        let ciphertext = cbc_encrypt(&plaintext, iv, key);

        assert_eq!(ciphertext.len(), 80);
    }
}