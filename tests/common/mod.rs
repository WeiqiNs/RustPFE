use ark_ec::pairing::Pairing;
use pfe::group::{DlogTable, ShapeError};
use pfe::ipfe::{bjk, kim, kks, lin, opt, tao};
use pfe::qfe::{bcfg, sgp};
use pfe::rand::Rng;

pub trait InnerProductScheme<E: Pairing> {
    const NAME: &'static str;
    type MasterKey;
    type Key;
    type PreparedKey;
    type Ciphertext;
    fn setup(n: usize, rng: &mut impl Rng) -> Self::MasterKey;
    fn keygen(msk: &Self::MasterKey, y: &[i64], rng: &mut impl Rng) -> Result<Self::Key, ShapeError>;
    fn encrypt(msk: &Self::MasterKey, x: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError>;
    fn prepare(sk: &Self::Key) -> Self::PreparedKey;
    fn decryptor(msk: &Self::MasterKey, lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64>;
    fn prepared_decryptor(
        msk: &Self::MasterKey,
        lo: i64,
        hi: i64,
    ) -> impl Fn(&Self::PreparedKey, &Self::Ciphertext) -> Option<i64>;
}

pub trait QuadraticScheme<E: Pairing> {
    const NAME: &'static str;
    type PublicKey;
    type MasterKey;
    type Key;
    type PreparedKey;
    type Ciphertext;
    fn setup(n: usize, rng: &mut impl Rng) -> (Self::PublicKey, Self::MasterKey);
    fn keygen(msk: &Self::MasterKey, f: &[Vec<i64>], rng: &mut impl Rng) -> Result<Self::Key, ShapeError>;
    fn encrypt(pk: &Self::PublicKey, x: &[i64], y: &[i64], rng: &mut impl Rng) -> Result<Self::Ciphertext, ShapeError>;
    fn prepare(sk: &Self::Key) -> Self::PreparedKey;
    fn decryptor(lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64>;
    fn prepared_decryptor(lo: i64, hi: i64) -> impl Fn(&Self::PreparedKey, &Self::Ciphertext) -> Option<i64>;
}

macro_rules! inner_product_scheme {
    ($adapter:ident, $name:literal, $module:ident, range) => {
        inner_product_scheme!(
            @define $adapter, $name, $module, |_msk, lo, hi|
            move |k, c| $module::decrypt(k, c, lo, hi)
        );
    };
    ($adapter:ident, $name:literal, $module:ident, table, |$msk:ident| $base:expr) => {
        inner_product_scheme!(
            @define $adapter, $name, $module, |$msk, lo, hi|
            {
                let table = DlogTable::new($base, lo, hi);
                move |k, c| $module::decrypt(&table, k, c)
            }
        );
    };
    (
        @define $adapter:ident, $name:literal, $module:ident,
        |$msk:ident, $lo:ident, $hi:ident| $decryptor:expr
    ) => {
        pub struct $adapter;

        impl<E: Pairing> InnerProductScheme<E> for $adapter {
            const NAME: &'static str = $name;
            type MasterKey = $module::MasterKey<E>;
            type Key = $module::Key<E>;
            type PreparedKey = $module::PreparedKey<E>;
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

            fn prepare(sk: &Self::Key) -> Self::PreparedKey {
                $module::prepare(sk)
            }

            fn decryptor(
                $msk: &Self::MasterKey,
                $lo: i64,
                $hi: i64,
            ) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
                $decryptor
            }

            fn prepared_decryptor(
                $msk: &Self::MasterKey,
                $lo: i64,
                $hi: i64,
            ) -> impl Fn(&Self::PreparedKey, &Self::Ciphertext) -> Option<i64> {
                $decryptor
            }
        }
    };
}

inner_product_scheme!(Bjk, "Bishop et al.", bjk, range);
inner_product_scheme!(Tao, "Tomida et al.", tao, table, |msk| msk.base);
inner_product_scheme!(Kim, "Kim et al.", kim, range);
inner_product_scheme!(Lin, "Lin", lin, table, |_msk| lin::base::<E>());
inner_product_scheme!(Kks, "Kim, Kim and Seo", kks, table, |_msk| kks::base::<E>());
inner_product_scheme!(Opt, "Ojaswi et al.", opt, table, |_msk| opt::base::<E>());

pub struct Bcfg;

impl<E: Pairing> QuadraticScheme<E> for Bcfg {
    const NAME: &'static str = "Baltico et al.";
    type PublicKey = bcfg::PublicKey<E>;
    type MasterKey = bcfg::MasterKey<E>;
    type Key = bcfg::Key<E>;
    type PreparedKey = bcfg::PreparedKey<E>;
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

    fn prepare(sk: &Self::Key) -> Self::PreparedKey {
        bcfg::prepare(sk)
    }

    fn decryptor(lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(bcfg::base::<E>(), lo, hi);
        move |k, c| bcfg::decrypt(&table, k, c)
    }

    fn prepared_decryptor(lo: i64, hi: i64) -> impl Fn(&Self::PreparedKey, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(bcfg::base::<E>(), lo, hi);
        move |k, c| bcfg::decrypt(&table, k, c)
    }
}

pub struct Sgp;

impl<E: Pairing> QuadraticScheme<E> for Sgp {
    const NAME: &'static str = "Dufour-Sans et al.";
    type PublicKey = sgp::PublicKey<E>;
    type MasterKey = sgp::MasterKey<E>;
    type Key = sgp::Key<E>;
    type PreparedKey = sgp::PreparedKey<E>;
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

    fn prepare(sk: &Self::Key) -> Self::PreparedKey {
        sgp::prepare(sk)
    }

    fn decryptor(lo: i64, hi: i64) -> impl Fn(&Self::Key, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(sgp::base::<E>(), lo, hi);
        move |k, c| sgp::decrypt(&table, k, c)
    }

    fn prepared_decryptor(lo: i64, hi: i64) -> impl Fn(&Self::PreparedKey, &Self::Ciphertext) -> Option<i64> {
        let table = DlogTable::new(sgp::base::<E>(), lo, hi);
        move |k, c| sgp::decrypt(&table, k, c)
    }
}
