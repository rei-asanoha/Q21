//! Imprime la page du portefeuille telle qu'elle est livree.
//!
//! Sert a la relire, a la rendre dans un navigateur, et a fabriquer la
//! demonstration publique — qui doit etre la meme page, sans quoi elle ne
//! demontre rien.
fn main() {
    print!("{}", q21_core::wallet_ui::PAGE);
}
