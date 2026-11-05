//! Polynomials over F2, with bit i representing the coefficient of X^i.
use num_bigint::BigUint;
pub type Poly = BigUint;

pub fn zero() -> Poly {
    Poly::from(0u8)
}

pub fn one() -> Poly {
    Poly::from(1u8)
}

pub fn bit(i: usize) -> Poly {
    one() << i
}

pub fn bits(a: &Poly) -> impl Iterator<Item = usize> + '_ {
    a.iter_u64_digits().enumerate().flat_map(|(i, mut w)| {
        let mut out = Vec::new();
        while w != 0 {
            let j = w.trailing_zeros() as usize;
            out.push(64 * i + j);
            w &= w - 1;
        }
        out
    })
}

pub fn degree(a: &Poly) -> usize {
    assert!(a.bits() > 0, "degree of zero");
    a.bits() as usize - 1
}

pub fn mul(a: &Poly, b: &Poly) -> Poly {
    bits(b).fold(zero(), |r, i| r ^ (a << i))
}

pub fn divmod(mut a: Poly, b: &Poly) -> (Poly, Poly) {
    let d = degree(b);
    let mut q = zero();
    while a.bits() > 0 && degree(&a) >= d {
        let s = degree(&a) - d;
        q.set_bit(s as u64, true);
        a ^= b << s;
    }
    (q, a)
}

pub fn rem(a: Poly, b: &Poly) -> Poly {
    divmod(a, b).1
}

pub fn mulmod(a: &Poly, b: &Poly, m: &Poly) -> Poly {
    rem(mul(a, b), m)
}

pub fn gcd(mut a: Poly, mut b: Poly) -> Poly {
    while b != zero() {
        let r = rem(a, &b);
        a = b;
        b = r;
    }
    a
}

pub fn inverse(a: &Poly, m: &Poly) -> Poly {
    let (mut r0, mut r1, mut s0, mut s1) = (m.clone(), rem(a.clone(), m), zero(), one());
    while r1 != zero() {
        let (q, r) = divmod(r0, &r1);
        r0 = r1;
        r1 = r;
        let ns = s0 ^ mul(&q, &s1);
        s0 = s1;
        s1 = ns;
    }
    assert_eq!(r0, one(), "polynomials are not coprime");
    rem(s0, m)
}

pub fn pow(a: &Poly, e: usize) -> Poly {
    (0..e).fold(one(), |r, _| mul(&r, a))
}

fn xpow(f: &Poly, k: usize) -> Poly {
    (0..k).fold(rem(bit(1), f), |r, _| mulmod(&r, &r, f))
}

pub fn irreducible(f: &Poly) -> bool {
    let n = degree(f);
    if n == 0 {
        return false;
    }
    if n == 1 {
        return true;
    }
    if !f.bit(0) || xpow(f, n) != rem(bit(1), f) {
        return false;
    }
    let mut factors = std::collections::BTreeSet::new();
    let mut v = n;
    let mut d = 2;
    while d * d <= v {
        while v.is_multiple_of(d) {
            factors.insert(d);
            v /= d;
        }
        d += 1;
    }
    if v > 1 {
        factors.insert(v);
    }
    factors
        .into_iter()
        .all(|q| gcd(f.clone(), rem(xpow(f, n / q) ^ bit(1), f)) == one())
}

pub fn combine(mask: &Poly, rows: &[Poly]) -> Poly {
    bits(mask).fold(zero(), |r, i| r ^ &rows[i])
}

pub fn parity(a: &Poly) -> bool {
    a.iter_u64_digits().fold(0, |p, w| p ^ w.count_ones()) & 1 != 0
}

pub fn reduction(q: &Poly, ncols: usize) -> Vec<Poly> {
    let mut rows = vec![zero(); degree(q)];
    let mut cur = one();
    for j in 0..ncols {
        for i in bits(&cur) {
            rows[i].set_bit(j as u64, true);
        }
        cur = rem(cur << 1, q);
    }
    rows
}

pub fn left_inverse(rows: &[Poly], ncols: usize) -> Vec<Poly> {
    let mut work: Vec<_> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.clone(), bit(i)))
        .collect();
    let mut used = vec![false; rows.len()];
    let mut pivots = Vec::new();
    for c in 0..ncols {
        let p = (0..rows.len())
            .find(|&i| !used[i] && work[i].0.bit(c as u64))
            .expect("evaluation map is not full rank");
        used[p] = true;
        pivots.push(p);
        let (pr, pt) = work[p].clone();
        for (i, (r, t)) in work.iter_mut().enumerate() {
            if i != p && r.bit(c as u64) {
                *r ^= &pr;
                *t ^= &pt;
            }
        }
    }
    pivots.into_iter().map(|p| work[p].1.clone()).collect()
}

pub fn product(moduli: &[Poly]) -> Poly {
    moduli.iter().fold(one(), |a, b| mul(&a, b))
}

pub fn crt_cols(moduli: &[Poly]) -> Vec<Poly> {
    let mt = product(moduli);
    let mut cols = Vec::new();
    for m in moduli {
        let (q, r) = divmod(mt.clone(), m);
        assert_eq!(r, zero(), "tree modulus does not divide M_tree");
        let e = mulmod(&q, &inverse(&q, m), &mt);
        for i in 0..degree(m) {
            cols.push(rem(&e << i, &mt));
        }
    }
    cols
}

pub fn modulus(lambda: usize) -> Poly {
    match lambda {
        128 | 192 => bit(lambda) ^ bit(7) ^ bit(2) ^ bit(1) ^ one(),
        256 => bit(256) ^ bit(10) ^ bit(5) ^ bit(2) ^ one(),
        _ => panic!("unsupported FAEST modulus"),
    }
}
