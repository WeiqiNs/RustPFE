use ark_ec::pairing::Pairing;
use pfe::group::{DlogTable, ShapeError};
use pfe::ipfe::{bjk, kim, kks, lin, opt, tao};
use pfe::qfe::{bcfg, sgp};
use pfe::rand::Rng;

pub trait InnerProductScheme<E: Pairing> {
    const NAME: &'static str;
    type MasterKey;
    type Key;
    type Ciphertext;
    fn setup(n: usize, rng: &mut impl Rng) -> Self::MasterKey;
    fn keygen(msk: &Self::MasterKey, y: &[i64], rng: &mut impl Rng) -> Result<Self::Key, ShapeError>;
    fn encrypt(msk: &Self::MasterKey, x: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError>;
    fn decryptor(msk: &Self::MasterKey, lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64>;
}

pub trait QuadraticScheme<E: Pairing> {
    const NAME: &'static str;
    type PublicKey;
    type MasterKey;
    type Key;
    type Ciphertext;
    fn setup(n: usize, rng: &mut impl Rng) -> (Self::PublicKey, Self::MasterKey);
    fn keygen(msk: &Self::MasterKey, f: &[Vec<i64>], rng: &mut impl Rng) -> Result<Self::Key, ShapeError>;
    fn encrypt(pk: &Self::PublicKey, x: &[i64], y: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError>;
    fn decryptor(pk: &Self::PublicKey, lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64>;
}

macro_rules! inner_product_scheme {
    ($adapter:ident, $name:literal, $module:ident, |$msk:ident, $lo:ident, $hi:ident| $decryptor:expr) => {
        pub struct $adapter;

        impl<E: Pairing> InnerProductScheme<E> for $adapter {
            const NAME: &'static str = $name;
            type MasterKey = $module::MasterKey<E>;
            type Key = $module::Key<E>;
            type Ciphertext = $module::Ciphertext<E>;

            fn setup(n: usize, rng: &mut impl Rng) -> Self::MasterKey {
                $module::setup(n, rng)
            }

            fn keygen(msk: &Self::MasterKey, y: &[i64], rng: &mut impl Rng) -> Result<Self::Key, ShapeError> {
                $module::keygen(msk, y, rng)
            }

            fn encrypt(msk: &Self::MasterKey, x: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError> {
                $module::encrypt(msk, x, rng)
            }

            fn decryptor(
                $msk: &Self::MasterKey,
                $lo: i64,
                $hi: i64,
            ) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
                $decryptor
            }
        }
    };
}

inner_product_scheme!(Bjk, "Bishop et al.", bjk, |_msk, lo, hi| {
    move |k, c| bjk::decrypt(k, c, lo, hi)
});
inner_product_scheme!(Tao, "Tomida et al.", tao, |msk, lo, hi| {
    let table = DlogTable::new(msk.base, lo, hi);
    move |k, c| tao::decrypt(&table, k, c)
});
inner_product_scheme!(Kim, "Kim et al.", kim, |_msk, lo, hi| {
    move |k, c| kim::decrypt(k, c, lo, hi)
});
inner_product_scheme!(Lin, "Lin", lin, |_msk, lo, hi| {
    let table = DlogTable::new(lin::base::<E>(), lo, hi);
    move |k, c| lin::decrypt(&table, k, c)
});
inner_product_scheme!(Kks, "Kim, Kim and Seo", kks, |_msk, lo, hi| {
    let table = DlogTable::new(kks::base::<E>(), lo, hi);
    move |k, c| kks::decrypt(&table, k, c)
});
inner_product_scheme!(Opt, "Ojaswi et al.", opt, |_msk, lo, hi| {
    let table = DlogTable::new(opt::base::<E>(), lo, hi);
    move |k, c| opt::decrypt(&table, k, c)
});

pub struct Bcfg;

impl<E: Pairing> QuadraticScheme<E> for Bcfg {
    const NAME: &'static str = "Baltico et al.";
    type PublicKey = bcfg::PublicKey<E>;
    type MasterKey = bcfg::MasterKey<E>;
    type Key = bcfg::Key<E>;
    type Ciphertext = bcfg::Ciphertext<E>;

    fn setup(n: usize, rng: &mut impl Rng) -> (Self::PublicKey, Self::MasterKey) {
        bcfg::setup(n, rng)
    }

    fn keygen(msk: &Self::MasterKey, f: &[Vec<i64>], rng: &mut impl Rng) -> Result<Self::Key, ShapeError> {
        bcfg::keygen(msk, f, rng)
    }

    fn encrypt(pk: &Self::PublicKey, x: &[i64], y: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError> {
        bcfg::encrypt(pk, x, y, rng)
    }

    fn decryptor(pk: &Self::PublicKey, lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(bcfg::base::<E>(), lo, hi);
        let pk = pk.clone();
        move |k, c| bcfg::decrypt(&table, &pk, k, c)
    }
}

pub struct Sgp;

impl<E: Pairing> QuadraticScheme<E> for Sgp {
    const NAME: &'static str = "Dufour-Sans et al.";
    type PublicKey = sgp::PublicKey<E>;
    type MasterKey = sgp::MasterKey<E>;
    type Key = sgp::Key<E>;
    type Ciphertext = sgp::Ciphertext<E>;

    fn setup(n: usize, rng: &mut impl Rng) -> (Self::PublicKey, Self::MasterKey) {
        sgp::setup(n, rng)
    }

    fn keygen(msk: &Self::MasterKey, f: &[Vec<i64>], _rng: &mut impl Rng) -> Result<Self::Key, ShapeError> {
        sgp::keygen(msk, f)
    }

    fn encrypt(pk: &Self::PublicKey, x: &[i64], y: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError> {
        sgp::encrypt(pk, x, y, rng)
    }

    fn decryptor(_pk: &Self::PublicKey, lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(sgp::base::<E>(), lo, hi);
        move |k, c| sgp::decrypt(&table, k, c)
    }
}
