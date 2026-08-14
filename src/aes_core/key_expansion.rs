use super::constants::{RCON, SBOX};

/// RotWord : fait tourner un mot de 4 octets d'une position vers la gauche.
pub fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

/// SubWord : applique la S-box à chacun des 4 octets d'un mot.
pub fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

/// Dérive les 44 mots de 4 octets nécessaires à AES-128, à partir
/// de la clé secrète initiale de 16 octets.
///
/// Tous les 4 mots, applique RotWord, SubWord puis un XOR avec la
/// constante de round RCON correspondante.
pub fn key_expansion(key: [u8; 16]) -> [[u8; 4]; 44] {
    let mut words: [[u8; 4]; 44] = [[0u8; 4]; 44];

    for i in 0..4 {
        words[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }

    for i in 4..44 {
        let mut temp = words[i - 1];

        if i % 4 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / 4];
        }

        words[i] = [
            words[i - 4][0] ^ temp[0],
            words[i - 4][1] ^ temp[1],
            words[i - 4][2] ^ temp[2],
            words[i - 4][3] ^ temp[3],
        ];
    }

    words
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie la rotation d'un mot de 4 octets.
    #[test]
    fn test_rot_word() {
        assert_eq!(rot_word([0x0c, 0x0d, 0x0e, 0x0f]), [0x0d, 0x0e, 0x0f, 0x0c]);
    }

    /// Vérifie l'application de la S-box à un mot.
    #[test]
    fn test_sub_word() {
        assert_eq!(sub_word([0x0d, 0x0e, 0x0f, 0x0c]), [0xd7, 0xab, 0x76, 0xfe]);
    }

    /// Vérifie l'enchaînement RotWord puis SubWord.
    #[test]
    fn test_rot_then_sub_word() {
        let w3 = [0x0c, 0x0d, 0x0e, 0x0f];
        let rotated = rot_word(w3);
        let result = sub_word(rotated);
        assert_eq!(result, [0xd7, 0xab, 0x76, 0xfe]);
    }

    /// Vérifie les 4 premiers mots (clé découpée) et W4 (premier mot dérivé) :
    /// couvre le découpage initial, RotWord, SubWord, RCON[1] et le XOR final.
    #[test]
    fn test_key_expansion_w4() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let words = key_expansion(key);

        assert_eq!(words[0], [0x00, 0x01, 0x02, 0x03]);
        assert_eq!(words[3], [0x0c, 0x0d, 0x0e, 0x0f]);
        assert_eq!(words[4], [0xd6, 0xaa, 0x74, 0xfd]);
    }

    /// Vérifie le dernier mot généré (words[43]), pour couvrir la boucle
    /// jusqu'au bout et pas seulement son tout début.
    #[test]
    fn test_key_expansion_last_word() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let words = key_expansion(key);

        assert_eq!(words[43], [0x4d, 0x2b, 0x30, 0xc5]);
    }
}
