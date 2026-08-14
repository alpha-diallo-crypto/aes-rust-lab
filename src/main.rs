mod aes_core;

fn main() {
    println!("=== gf256 : arithmétique de base dans GF(2^8) ===");
    let xtime_result = aes_core::gf256::xtime(0x57);
    let add_result = aes_core::gf256::add(0x53, 0xca);
    let mul_result = aes_core::gf256::mul(0x53, 0xca);
    let pow_result = aes_core::gf256::pow(0x53, 13);
    let inv_result = aes_core::gf256::inv(0x57);

    println!("xtime(0x57) = 0x{:02x}", xtime_result);
    println!("add(0x53, 0xca) = 0x{:02x}", add_result);
    println!("mul(0x53, 0xca) = 0x{:02x}", mul_result);
    println!("pow(0x53, 13) = 0x{:02x}", pow_result);
    println!("inv(0x57) = 0x{:02x}", inv_result);
    println!();

    println!("=== state : conversion tableau <-> matrice 4x4 ===");
    let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let state = aes_core::state::State::from_bytes(input);
    state.print();
    println!("{:02x?}", state.to_bytes());
    println!();

    println!("=== transformations : sub_bytes, shift_rows, mix_columns ===");
    let mut demo_state = aes_core::state::State::from_bytes(input);

    demo_state.sub_bytes();
    println!("-- sub_bytes --");
    demo_state.print();

    demo_state.shift_rows();
    println!("-- shift_rows --");
    demo_state.print();

    demo_state.mix_columns();
    println!("-- mix_columns --");
    demo_state.print();
    println!();

    println!("=== add_round_key ===");
    let demo_input: [u8; 16] = [
        5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80,
    ];
    let key_bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut key_demo_state = aes_core::state::State::from_bytes(demo_input);
    let round_key = aes_core::state::State::from_bytes(key_bytes);

    key_demo_state.add_round_key(&round_key);
    key_demo_state.print();
    println!();

    println!("=== key_expansion : dérivation des 44 mots de clé de round ===");
    let demo_key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let round_keys = aes_core::key_expansion::key_expansion(demo_key);

    for (i, word) in round_keys.iter().enumerate() {
        println!("W{} = {:02x?}", i, word);
    }
    println!();

    println!("=== sbox : reconstruction indépendante de la S-box ===");
    let byte: u8 = 0x67;
    println!("sbox(0x67) = 0x{:02x}", aes_core::sbox::sbox(byte));
    println!();

    println!("=== cipher : AES-128 complet, vecteur de référence FIPS-197 ===");
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    let ciphertext = aes_core::cipher::encrypt(plaintext, key);

    println!("plaintext  = {:02x?}", plaintext);
    println!("key        = {:02x?}", key);
    println!("ciphertext = {:02x?}", ciphertext);
}
