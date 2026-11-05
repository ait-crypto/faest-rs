use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;
use hybrid_array::{Array, typenum::Unsigned};
use rand_core::CryptoRng;
#[cfg(feature = "zeroize")]
use zeroize::Zeroizing;

use crate::{
    Error,
    bavc::{BatchVectorCommitment, BavcOpenResult},
    declassify,
    fields::{Field, FromBit},
    internal_keys::{PublicKeyView, SecretKey, SecretKeyView, UnpackedSecretKeyView},
    parameter::{BaseParameters, FAESTParameters, NMask, OWFField, OWFParameters, TauParameters},
    prg::{IV, IVSize},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::{Reader, decode_all_chall_3, get_bit, xor_arrays_into},
    vole::{VoleCommitmentCRef, VoleCommitmentCRefMut, volecommit, volereconstruct},
    zk::{Challenge, owf_prove, owf_verify},
};

type O<P> = <P as FAESTParameters>::OWF;
type B<P> = <O<P> as OWFParameters>::BaseParams;
type F<P> = OWFField<O<P>>;
type RO<P> = <B<P> as BaseParameters>::RandomOracle;
type Chall1<P> = Array<u8, <B<P> as BaseParameters>::Chall1>;

/// Shared offsets used to construct the borrowed signature views
struct SignatureLayout {
    c: Range<usize>,
    c_mult: Range<usize>,
    u_tilde: Range<usize>,
    d: Range<usize>,
    a_tilde: Range<usize>,
    decom_i: Range<usize>,
    chall_3: Range<usize>,
    iv_pre: Range<usize>,
    ctr: Range<usize>,
}

impl SignatureLayout {
    fn new<P: FAESTParameters>() -> Self {
        let n = <O<P> as OWFParameters>::LambdaBytes::USIZE;
        let ell = <O<P> as OWFParameters>::LBytes::USIZE;
        let mut offset = 0;
        let mut take = |size| {
            let start = offset;
            offset += size;
            start..offset
        };
        let layout = Self {
            c: take((<P::Tau as TauParameters>::Tau::USIZE - 1) * ell),
            c_mult: take(NMask::USIZE * P::Tau::VOLE_TABLES.gates.div_ceil(8)),
            u_tilde: take(4 * n),
            d: take(ell),
            a_tilde: take(6 * n),
            decom_i: take(P::get_decom_size()),
            chall_3: take(n),
            iv_pre: take(IVSize::USIZE),
            ctr: take(4),
        };
        debug_assert_eq!(offset, P::SIGNATURE_SIZE);
        layout
    }
}

/// Borrows the prover's signature
struct SignatureRefMut<'a, P: FAESTParameters> {
    c: &'a mut [u8],
    c_mult: &'a mut [u8],
    u_tilde: &'a mut [u8],
    d: &'a mut [u8],
    a_tilde: &'a mut [u8],
    decom_i: &'a mut [u8],
    chall_3: &'a mut [u8],
    iv_pre: &'a mut [u8],
    ctr: &'a mut [u8],
    pd: PhantomData<P>,
}

impl<'a, P: FAESTParameters> From<&'a mut [u8]> for SignatureRefMut<'a, P> {
    fn from(value: &'a mut [u8]) -> Self {
        debug_assert_eq!(value.len(), P::SIGNATURE_SIZE);
        let layout = SignatureLayout::new::<P>();
        let (c, value) = value.split_at_mut(layout.c.len());
        let (c_mult, value) = value.split_at_mut(layout.c_mult.len());
        let (u_tilde, value) = value.split_at_mut(layout.u_tilde.len());
        let (d, value) = value.split_at_mut(layout.d.len());
        let (a_tilde, value) = value.split_at_mut(layout.a_tilde.len());
        let (decom_i, value) = value.split_at_mut(layout.decom_i.len());
        let (chall_3, value) = value.split_at_mut(layout.chall_3.len());
        let (iv_pre, ctr) = value.split_at_mut(layout.iv_pre.len());
        Self {
            c,
            c_mult,
            u_tilde,
            d,
            a_tilde,
            decom_i,
            chall_3,
            iv_pre,
            ctr,
            pd: PhantomData,
        }
    }
}

impl<P: FAESTParameters> SignatureRefMut<'_, P> {
    fn save_opening_and_ctr(&mut self, opening: &BavcOpenResult<'_>, ctr: u32) {
        let mut offset = 0;
        for bytes in opening.coms.iter().chain(&opening.nodes) {
            self.decom_i[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        self.decom_i[offset..].fill(0);
        self.ctr.copy_from_slice(&ctr.to_le_bytes());
    }
}

/// Borrows the signature received by the verifier
struct SignatureRef<'a, P: FAESTParameters> {
    c: &'a [u8],
    c_mult: &'a [u8],
    u_tilde: &'a [u8],
    d: &'a [u8],
    a_tilde: &'a [u8],
    decom_i: &'a [u8],
    chall_3: &'a [u8],
    iv_pre: &'a [u8],
    ctr: &'a [u8],
    pd: PhantomData<P>,
}

impl<'a, P: FAESTParameters> From<&'a [u8]> for SignatureRef<'a, P> {
    fn from(value: &'a [u8]) -> Self {
        debug_assert_eq!(value.len(), P::SIGNATURE_SIZE);
        let layout = SignatureLayout::new::<P>();
        Self {
            c: &value[layout.c],
            c_mult: &value[layout.c_mult],
            u_tilde: &value[layout.u_tilde],
            d: &value[layout.d],
            a_tilde: &value[layout.a_tilde],
            decom_i: &value[layout.decom_i],
            chall_3: &value[layout.chall_3],
            iv_pre: &value[layout.iv_pre],
            ctr: &value[layout.ctr],
            pd: PhantomData,
        }
    }
}

impl<'a, P: FAESTParameters> SignatureRef<'a, P> {
    fn parse_opening(&self) -> BavcOpenResult<'a> {
        let n = <O<P> as OWFParameters>::LambdaBytes::USIZE;
        let com_size = n * <O<P> as OWFParameters>::NLeafCommit::USIZE;
        let (coms, nodes) = self
            .decom_i
            .split_at(com_size * <P::Tau as TauParameters>::Tau::USIZE);
        BavcOpenResult {
            coms: coms.chunks_exact(com_size).collect(),
            nodes: nodes.chunks_exact(n).collect(),
        }
    }

    fn parse_ctr(&self) -> u32 {
        u32::from_le_bytes(self.ctr.try_into().unwrap())
    }
}

fn hash_mu<P: FAESTParameters>(
    pk: &PublicKeyView<'_, O<P>>,
    msg: &[u8],
) -> Array<u8, <O<P> as OWFParameters>::LambdaBytesTimes2> {
    let mut h = RO::<P>::h2_0_init();
    h.update(pk.owf_input);
    h.update(pk.owf_output);
    h.update(msg);
    h.finish().read_into()
}

fn hash_r_iv<P: FAESTParameters>(
    r: &mut [u8],
    iv_pre: &mut [u8],
    key: &[u8],
    mu: &[u8],
    rho: &[u8],
) {
    // line 4
    let mut h3_hasher = RO::<P>::h3_init();
    h3_hasher.update(key);
    h3_hasher.update(mu);
    h3_hasher.update(rho);

    let mut h3_reader = h3_hasher.finish();
    h3_reader.read(r);
    h3_reader.read(iv_pre);
}

fn hash_iv<P: FAESTParameters>(iv_pre: &[u8], mu: &[u8]) -> IV {
    let mut h = RO::<P>::h4_init();
    h.update(iv_pre);
    h.update(mu);
    h.finish().read_into()
}

fn challenge_1<P: FAESTParameters>(
    mu: &[u8],
    com: &[u8],
    c: &[u8],
    c_mult: &[u8],
    iv_pre: &[u8],
) -> Chall1<P> {
    let mut h = RO::<P>::h2_1_init();
    for bytes in [mu, com, c, c_mult, iv_pre] {
        h.update(bytes);
    }
    h.finish().read_into()
}

fn challenge_2<P: FAESTParameters>(
    chall1: &Chall1<P>,
    u_tilde: &[u8],
    v_tilde: &[u8],
    d: &[u8],
) -> Challenge<O<P>> {
    let mut h = RO::<P>::h2_2_init();
    for bytes in [chall1.as_slice(), u_tilde, v_tilde, d] {
        h.update(bytes);
    }
    h.finish().read_into()
}

fn challenge_3_init<P: FAESTParameters>(
    chall2: &Challenge<O<P>>,
    a0: F<P>,
    a: &[u8],
) -> <RO<P> as RandomOracle>::Hasher<11> {
    let mut h = RO::<P>::h2_3_init();
    h.update(chall2);
    h.update(&a0.as_bytes());
    h.update(a);
    h
}

fn challenge_3<P: FAESTParameters>(
    prefix: &<RO<P> as RandomOracle>::Hasher<11>,
    ctr: u32,
) -> Array<u8, <O<P> as OWFParameters>::LambdaBytes> {
    let mut h = prefix.clone();
    h.update(&ctr.to_le_bytes());
    h.finish().read_into()
}

fn check_challenge_3<P: FAESTParameters>(challenge: &[u8]) -> bool {
    (<O<P> as OWFParameters>::Lambda::USIZE - P::WGRIND::USIZE
        ..<O<P> as OWFParameters>::Lambda::USIZE)
        .all(|bit| get_bit(challenge, bit) == 0)
}

/// Transpose the witness once into field rows
/// TODO: use optimize matrix transpose
fn witness_rows<P: FAESTParameters>(
    columns: &Array<Array<u8, <O<P> as OWFParameters>::LBytes>, <O<P> as OWFParameters>::Lambda>,
) -> Box<Array<F<P>, <O<P> as OWFParameters>::L>> {
    let mut rows = Box::<Array<F<P>, <O<P> as OWFParameters>::L>>::default();
    for (bit, row) in rows.iter_mut().enumerate() {
        let mut bytes = Array::<u8, <O<P> as OWFParameters>::LambdaBytes>::default();
        for (column, data) in columns.iter().enumerate() {
            bytes[column / 8] |= get_bit(data, bit) << (column % 8);
        }
        *row = F::<P>::from(bytes.as_slice());
    }
    rows
}

/// Hash witness rows and six proof masks, using the last four masks as output masks
fn consistency_hash<P: FAESTParameters>(
    chall1: &Chall1<P>,
    rows: impl Iterator<Item = F<P>>,
    masks: &Array<Array<u8, <O<P> as OWFParameters>::LambdaBytes>, NMask>,
) -> Array<u8, <B<P> as BaseParameters>::VoleHasherOutputLength> {
    let mut bytes = Vec::with_capacity(
        (<O<P> as OWFParameters>::L::USIZE + NMask::USIZE)
            * <O<P> as OWFParameters>::LambdaBytes::USIZE,
    );
    for row in rows {
        bytes.extend(&row.as_bytes());
    }
    for mask in masks {
        bytes.extend(mask);
    }
    <B<P> as BaseParameters>::VoleHasher::new_vole_hasher(chall1).process(&bytes)
}

#[inline]
pub(crate) fn faest_keygen<O, R>(rng: &mut R) -> SecretKey<O>
where
    O: OWFParameters,
    R: CryptoRng + ?Sized,
{
    O::keygen_with_rng(rng)
}

#[inline]
pub(crate) fn faest_sign<P: FAESTParameters>(
    msg: &[u8],
    sk: SecretKeyView<'_, O<P>>,
    rho: &[u8],
    signature: &mut [u8],
) -> Result<(), Error> {
    let signature = SignatureRefMut::<P>::from(signature);
    // line 16
    // TODO: consider directly returning Zeroising array from extendwitness
    let w = O::<P>::extendwitness(sk.owf_key, sk.pk.owf_input);
    #[cfg(feature = "zeroize")]
    let w = Zeroizing::new(*w);
    sign::<P>(msg, sk, &w, rho, signature)
}

#[inline]
pub(crate) fn faest_unpacked_sign<P: FAESTParameters>(
    msg: &[u8],
    sk: UnpackedSecretKeyView<'_, O<P>>,
    rho: &[u8],
    signature: &mut [u8],
) -> Result<(), Error> {
    let signature = SignatureRefMut::<P>::from(signature);
    sign::<P>(msg, sk.sk, sk.wit, rho, signature)
}

fn sign<P: FAESTParameters>(
    msg: &[u8],
    sk: SecretKeyView<'_, O<P>>,
    witness: &Array<u8, <O<P> as OWFParameters>::LBytes>,
    rho: &[u8],
    mut sig: SignatureRefMut<'_, P>,
) -> Result<(), Error> {
    // lines 2–4
    let mu = hash_mu::<P>(&sk.pk, msg);
    let vole = {
        #[cfg(not(feature = "zeroize"))]
        let mut r = Array::default();
        #[cfg(feature = "zeroize")]
        let mut r = Zeroizing::new(Array::default());
        hash_r_iv::<P>(&mut r, sig.iv_pre, sk.owf_key, &mu, rho);
        let iv = hash_iv::<P>(sig.iv_pre, &mu);

        // line 6
        volecommit::<P>(VoleCommitmentCRefMut::new(sig.c), sig.c_mult, &r, &iv)
    };
    let v_rows = witness_rows::<P>(&vole.v);

    // lines 7–14
    let chall1 = challenge_1::<P>(&mu, &vole.com, sig.c, sig.c_mult, sig.iv_pre);
    let u_tilde = consistency_hash::<P>(
        &chall1,
        (0..<O<P> as OWFParameters>::L::USIZE).map(|i| F::<P>::from_bit(get_bit(&vole.u, i))),
        &vole.u_bar,
    );
    sig.u_tilde.copy_from_slice(&u_tilde);
    let v_tilde = consistency_hash::<P>(&chall1, v_rows.iter().copied(), &vole.v_bar);

    // lines 16–20
    xor_arrays_into(sig.d, witness, &vole.u);
    let chall2 = challenge_2::<P>(&chall1, sig.u_tilde, &v_tilde, sig.d);
    let masks = core::array::from_fn(|i| {
        (
            F::<P>::from(vole.u_bar[i].as_slice()),
            F::<P>::from(vole.v_bar[i].as_slice()),
        )
    });
    let proof = owf_prove::<O<P>>(witness, &v_rows, &masks, &sk.pk, &chall2);

    // line 30: write a_tilde 1..d_zk -1
    for (chunk, coefficient) in sig
        .a_tilde
        .chunks_exact_mut(<O<P> as OWFParameters>::LambdaBytes::USIZE)
        .zip(&proof[1..])
    {
        chunk.copy_from_slice(&coefficient.as_bytes());
    }

    // lines 21–30
    let h_init = challenge_3_init::<P>(&chall2, proof[0], sig.a_tilde);
    for ctr in 0..=u32::MAX {
        let chall_3 = challenge_3::<P>(&h_init, ctr);
        // declassify chall_3 which is put into the signature
        declassify!(&chall_3);
        if !check_challenge_3::<P>(&chall_3) {
            continue;
        }
        let indices = decode_all_chall_3::<P::Tau>(&chall_3);
        if let Some(opening) = P::BAVC::open(&vole.decom, &indices) {
            sig.save_opening_and_ctr(&opening, ctr);
            sig.chall_3.copy_from_slice(&chall_3);
            return Ok(());
        }
    }
    Err(Error::new())
}

pub(crate) fn faest_verify<P: FAESTParameters>(
    msg: &[u8],
    pk: &PublicKeyView<'_, O<P>>,
    sig: &[u8],
) -> Result<(), Error> {
    // lines 1–7
    let sig = SignatureRef::<P>::from(sig);
    let mu = hash_mu::<P>(pk, msg);
    let iv = hash_iv::<P>(sig.iv_pre, &mu);
    let challenge: &Array<u8, <O<P> as OWFParameters>::LambdaBytes> =
        sig.chall_3.try_into().map_err(|_| Error::new())?;
    if !check_challenge_3::<P>(challenge) {
        return Err(Error::new());
    }

    // lines 9–13
    let opening = sig.parse_opening();
    let rec = volereconstruct::<P>(
        challenge,
        &opening,
        VoleCommitmentCRef::new(sig.c),
        sig.c_mult,
        &iv,
    )
    .ok_or_else(Error::new)?;
    let chall1 = challenge_1::<P>(&mu, &rec.com, sig.c, sig.c_mult, sig.iv_pre);
    let mut q_rows = witness_rows::<P>(&rec.q);

    // lines 14–18
    let mut d_hash = consistency_hash::<P>(&chall1, q_rows.iter().copied(), &rec.q_bar);
    let delta = F::<P>::from(rec.delta.as_slice());
    for (chunk, u) in d_hash
        .chunks_exact_mut(<O<P> as OWFParameters>::LambdaBytes::USIZE)
        .zip(
            sig.u_tilde
                .chunks_exact(<O<P> as OWFParameters>::LambdaBytes::USIZE),
        )
    {
        let value = F::<P>::from(&*chunk) + delta * F::<P>::from(u);
        chunk.copy_from_slice(&value.as_bytes());
    }
    let chall2 = challenge_2::<P>(&chall1, sig.u_tilde, &d_hash, sig.d);

    // line 20
    let a = core::array::from_fn(|i| {
        let start = i * <O<P> as OWFParameters>::LambdaBytes::USIZE;
        F::<P>::from(&sig.a_tilde[start..start + <O<P> as OWFParameters>::LambdaBytes::USIZE])
    });
    let q_bar = core::array::from_fn(|i| F::<P>::from(rec.q_bar[i].as_slice()));
    let d = sig.d.try_into().map_err(|_| Error::new())?;
    let a0 = owf_verify::<O<P>>(d, &mut q_rows, &q_bar, pk, &chall2, delta, &a);

    // lines 21–22
    let prefix = challenge_3_init::<P>(&chall2, a0, sig.a_tilde);
    let ctr = sig.parse_ctr();
    if challenge_3::<P>(&prefix, ctr) == *challenge {
        Ok(())
    } else {
        Err(Error::new())
    }
}

#[cfg(test)]
#[path = "../tests/data/faest_tvs.rs"]
mod test_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        internal_keys::{PublicKey, UnpackedSecretKey},
        parameter::*,
    };
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    struct SignatureFixture {
        sk: &'static [u8],
        pk: &'static [u8],
        witness: &'static [u8],
        signature: &'static [u8],
    }

    // These vectors are transcribed from faest-ref's tests/faest_tvs.hpp.

    fn secret_key<P: FAESTParameters>(fixture: &SignatureFixture) -> SecretKey<O<P>> {
        let sk = SecretKey::try_from(fixture.sk).unwrap();
        assert_eq!(sk.pk, PublicKey::try_from(fixture.pk).unwrap());
        sk
    }

    /// Locate the implicit zero padding by marking the paths hidden by the challenge.
    fn padding_start<P: FAESTParameters>(sig: &[u8], layout: &SignatureLayout) -> usize {
        let indices = decode_all_chall_3::<P::Tau>(&sig[layout.chall_3.clone()]);
        let mut marked = vec![false; 2 * P::Tau::L - 1];
        for (i, &index) in indices.iter().enumerate() {
            let mut node = P::Tau::pos_in_tree(i, index as usize);
            marked[node] = true;
            while node > 0 {
                node = (node - 1) / 2;
                marked[node] = true;
            }
        }
        let nodes = (0..P::Tau::L - 1)
            .filter(|&i| marked[2 * i + 1] ^ marked[2 * i + 2])
            .count();
        layout.decom_i.start
            + (<P::Tau as TauParameters>::Tau::USIZE * <O<P> as OWFParameters>::NLeafCommit::USIZE
                + nodes)
                * <O<P> as OWFParameters>::LambdaBytes::USIZE
    }

    fn check<P: FAESTParameters>(fixture: &SignatureFixture) {
        let sk = secret_key::<P>(fixture);
        faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), fixture.signature).unwrap();

        // Dirty output storage also checks that signing writes all padding bytes.
        let mut sig = vec![0xff; P::SIGNATURE_SIZE];
        faest_sign::<P>(
            &test_vectors::MESSAGE,
            sk.as_view(),
            &test_vectors::RANDOM_SEED,
            &mut sig,
        )
        .unwrap();
        assert_eq!(
            sig.as_slice(),
            fixture.signature,
            "reference signature mismatch"
        );
        faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), &sig).unwrap();

        let cached = UnpackedSecretKey::from(sk);
        assert_eq!(
            cached.wit.as_slice(),
            fixture.witness,
            "reference witness mismatch"
        );
        let mut cached_sig = vec![0xa5; P::SIGNATURE_SIZE];
        faest_unpacked_sign::<P>(
            &test_vectors::MESSAGE,
            cached.as_view(),
            &test_vectors::RANDOM_SEED,
            &mut cached_sig,
        )
        .unwrap();
        assert_eq!(sig, cached_sig, "cached witness signature mismatch");
    }

    fn reject_malformed<P: FAESTParameters>(fixture: &SignatureFixture) {
        let sk = secret_key::<P>(fixture);
        let layout = SignatureLayout::new::<P>();
        let mut msg = test_vectors::MESSAGE.to_vec();
        msg[0] ^= 1;
        assert!(faest_verify::<P>(&msg, &sk.pk.as_view(), fixture.signature).is_err());
        for output in [false, true] {
            let mut pk = sk.pk.clone();
            if output {
                pk.owf_output[0] ^= 1;
            } else {
                pk.owf_input[0] ^= 1;
            }
            assert!(
                faest_verify::<P>(&test_vectors::MESSAGE, &pk.as_view(), fixture.signature)
                    .is_err()
            );
        }

        // Mutate each signature component
        let positions = [
            layout.c.start,
            layout.c_mult.start,
            layout.u_tilde.start,
            layout.d.start,
            layout.decom_i.start,
            layout.chall_3.start,
            layout.iv_pre.start,
            layout.ctr.start,
        ];
        for pos in positions.into_iter().chain(
            (0..6).map(|i| layout.a_tilde.start + i * <O<P> as OWFParameters>::LambdaBytes::USIZE),
        ) {
            let mut sig = fixture.signature.to_vec();
            sig[pos] ^= 1;
            assert!(
                faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), &sig).is_err(),
                "mutation at {pos}"
            );
        }
        let mut sig = fixture.signature.to_vec();
        sig[layout.chall_3.end - 1] |= 0x80;
        assert!(faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), &sig).is_err());

        // When the reference opening leaves padding, every padding byte must be zero.
        let pad = padding_start::<P>(fixture.signature, &layout);
        assert!(pad <= layout.decom_i.end);
        if pad < layout.decom_i.end {
            let mut sig = fixture.signature.to_vec();
            sig[pad] = 1;
            assert!(faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), &sig).is_err());
            sig[pad] = 0;
            sig[layout.decom_i.end - 1] = 1;
            assert!(faest_verify::<P>(&test_vectors::MESSAGE, &sk.pk.as_view(), &sig).is_err());
        }
    }

    macro_rules! parameter_tests {
        ($($name:ident: $p:ty),* $(,)?) => {$(
            mod $name {
                use super::*;
                const FIXTURE: SignatureFixture = SignatureFixture {
                    sk: &test_vectors::$name::SK,
                    pk: &test_vectors::$name::PK,
                    witness: &test_vectors::$name::WITNESS,
                    signature: &test_vectors::$name::SIGNATURE,
                };
                #[test]
                fn reference_signatures() { check::<$p>(&FIXTURE); }
                #[test]
                fn malformed_signatures() { reject_malformed::<$p>(&FIXTURE); }
            }
        )*};
    }
    parameter_tests! {
        faest_128s: FAEST128sParameters,
        faest_128f: FAEST128fParameters,
        faest_192s: FAEST192sParameters,
        faest_192f: FAEST192fParameters,
        faest_256s: FAEST256sParameters,
        faest_256f: FAEST256fParameters,
        faest_em_128s: FAESTEM128sParameters,
        faest_em_128f: FAESTEM128fParameters,
        faest_em_192s: FAESTEM192sParameters,
        faest_em_192f: FAESTEM192fParameters,
        faest_em_256s: FAESTEM256sParameters,
        faest_em_256f: FAESTEM256fParameters,
    }
}
