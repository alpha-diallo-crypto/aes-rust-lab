/// Représente l'état AES sous la forme d'une matrice 4×4 d'octets.
///
/// Le remplissage suit la convention FIPS-197 : les octets d'entrée
/// sont placés colonne par colonne, pas ligne par ligne.
pub struct State {
    pub bytes: [[u8; 4]; 4],
}

impl State {
    /// Construit un état AES à partir d'un bloc de 16 octets.
    ///
    /// Le remplissage se fait colonne par colonne : pour un octet
    /// à la position `i` du tableau d'entrée, sa ligne vaut `i % 4`
    /// et sa colonne vaut `i / 4`.
    pub fn from_bytes(input: [u8; 16]) -> State {
        let mut bytes = [[0u8; 4]; 4];

        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            bytes[row][col] = input[i];
        }

        State { bytes }
    }

    /// Affiche la matrice sous forme de tableau 4x4, aligné.
    pub fn print(&self) {
        for row in 0..4 {
            for col in 0..4 {
                print!("{:3} ", self.bytes[row][col]);
            }
            println!();
        }
    }

    /// Reconvertit l'état AES en un bloc de 16 octets.
    ///
    /// Opération inverse de `from_bytes` : reprend la même
    /// correspondance ligne/colonne pour reconstruire l'ordre d'origine.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut output = [0u8; 16];
        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            output[i] = self.bytes[row][col];
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que from_bytes place bien les octets colonne par colonne,
    /// sur trois positions représentatives (début, milieu, fin).
    #[test]
    fn test_from_bytes() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let state = State::from_bytes(input);

        assert_eq!(state.bytes[2][1], 6);
        assert_eq!(state.bytes[0][0], 0);
        assert_eq!(state.bytes[3][3], 15);
    }

    /// Vérifie que to_bytes est bien l'inverse de from_bytes :
    /// l'aller-retour doit redonner exactement les données de départ.
    #[test]
    fn test_from_to_bytes() {
        let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let state = State::from_bytes(input);
        let output = state.to_bytes();
        assert_eq!(input, output);
    }
}
