//! Specialized degree-six/eight multiplication via F4 towers.

use super::{Alg, poly::*};

fn fm(a: usize, b: usize) -> usize {
    [[0, 0, 0, 0], [0, 1, 2, 3], [0, 2, 3, 1], [0, 3, 1, 2]][a][b]
}

fn fp(t: usize, j: usize) -> usize {
    (0..j).fold(1, |r, _| fm(r, t))
}

fn mul4(a: &[usize], b: &[usize]) -> Vec<usize> {
    let mut out = vec![0; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] ^= fm(x, y);
        }
    }
    out
}

fn rem4(a: &[usize], q: &[usize]) -> Vec<usize> {
    let d = q.len() - 1;
    let mut w = a.to_vec();
    for i in (d..w.len()).rev() {
        let c = w[i];
        for j in 0..=d {
            w[i - d + j] ^= fm(c, q[j]);
        }
    }
    w.resize(d, 0);
    w
}

fn tuples(n: usize) -> Vec<Vec<usize>> {
    (0..4usize.pow(n as u32))
        .map(|i| (0..n).map(|j| (i >> (2 * (n - 1 - j))) & 3).collect())
        .collect()
}

fn roots(p: &[usize]) -> bool {
    (0..4).any(|t| p.iter().rev().fold(0, |l, &r| fm(l, t) ^ r) == 0)
}

fn irreducibles4(m: usize) -> Vec<Vec<usize>> {
    let quads = if m == 4 { irreducibles4(2) } else { Vec::new() };
    tuples(m)
        .into_iter()
        .filter_map(|mut p| {
            p.push(1);
            if roots(&p) || quads.iter().any(|q| rem4(&p, q).iter().all(|&v| v == 0)) {
                None
            } else {
                Some(p)
            }
        })
        .collect()
}

fn xcols(q: &[usize], n: usize) -> Vec<Vec<usize>> {
    let mut cur = vec![0; q.len() - 1];
    cur[0] = 1;
    (0..n)
        .map(|_| {
            let r = cur.clone();
            cur.insert(0, 0);
            cur = rem4(&cur, q);
            r
        })
        .collect()
}

fn inv4(m: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = m.len();
    let mut a = m.to_vec();
    for (i, r) in a.iter_mut().enumerate() {
        r.resize(2 * n, 0);
        r[n + i] = 1;
    }
    for c in 0..n {
        let p = (c..n)
            .find(|&i| a[i][c] != 0)
            .expect("F4 matrix is singular");
        a.swap(c, p);
        let inv = [0, 1, 3, 2][a[c][c]];
        for v in &mut a[c] {
            *v = fm(inv, *v);
        }
        let pivot = a[c].clone();
        for (i, r) in a.iter_mut().enumerate() {
            if i != c {
                let factor = r[c];
                for j in 0..2 * n {
                    r[j] ^= fm(factor, pivot[j]);
                }
            }
        }
    }
    a.into_iter().map(|r| r[n..].to_vec()).collect()
}

fn full4(m: usize) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let mut gates = Vec::new();
    let mut ev = Vec::new();
    let mut r4 = Vec::new();
    for t in 0..if m == 2 { 2 } else { 4 } {
        r4.push(vec![(gates.len(), 1)]);
        gates.push((0..m).map(|j| fp(t, j)).collect());
        ev.push((0..2 * m - 1).map(|j| fp(t, j)).collect());
    }
    r4.push(vec![(gates.len(), 1)]);
    let mut inf = vec![0; m];
    inf[m - 1] = 1;
    gates.push(inf);
    let mut inf = vec![0; 2 * m - 1];
    inf[2 * m - 2] = 1;
    ev.push(inf);
    if m == 4 {
        let q = irreducibles4(2).remove(0);
        let (beta, alpha) = (q[0], q[1]);
        let cols = xcols(&q, m);
        let ga = gates.len();
        gates.push(cols.iter().map(|c| c[0]).collect());
        gates.push(cols.iter().map(|c| c[1]).collect());
        gates.push(cols.iter().map(|c| c[0] ^ c[1]).collect());
        let cols = xcols(&q, 2 * m - 1);
        ev.push(cols.iter().map(|c| c[0]).collect());
        ev.push(cols.iter().map(|c| c[1]).collect());
        r4.push(vec![(ga, 1), (ga + 1, beta)]);
        r4.push(vec![(ga, 1), (ga + 1, 1 ^ alpha), (ga + 2, 1)]);
    }
    let inv = inv4(&ev);
    let mut w = vec![vec![0; gates.len()]; 2 * m - 1];
    for k in 0..2 * m - 1 {
        for (j, r) in r4.iter().enumerate() {
            for &(g, c) in r {
                w[k][g] ^= fm(inv[k][j], c);
            }
        }
    }
    (gates, w)
}

fn tbits(t: &[usize]) -> Poly {
    t.iter()
        .enumerate()
        .fold(zero(), |r, (j, &c)| r | (Poly::from(c) << (2 * j)))
}

fn form(l: &[usize], rows: &[Poly]) -> (Poly, Poly) {
    let (mut p, mut r) = (zero(), zero());
    for (j, &c) in l.iter().enumerate() {
        let (pj, rj) = (&rows[2 * j], &rows[2 * j + 1]);
        if c & 1 != 0 {
            p ^= pj;
            r ^= rj;
        }
        if c & 2 != 0 {
            p ^= rj;
            r ^= pj ^ rj;
        }
    }
    (p, r)
}

pub fn tower(q: &Poly, na: usize, nb: usize) -> (Alg, Vec<Poly>) {
    let d = degree(q);
    let m = d / 2;
    let modulus = irreducibles4(m).remove(0);
    let (gates4, w4) = full4(m);
    let rq = xcols(&modulus, 2 * m - 1);
    let ng = gates4.len();
    let mut wm = vec![vec![0; ng]; m];
    for k in 0..m {
        for j in 0..2 * m - 1 {
            for g in 0..ng {
                wm[k][g] ^= fm(rq[j][k], w4[j][g]);
            }
        }
    }
    let rho = tuples(m)
        .into_iter()
        .find(|c| {
            let mut acc = vec![0; m];
            for i in (0..=d).rev() {
                acc = rem4(&mul4(&acc, c), &modulus);
                if q.bit(i as u64) {
                    acc[0] ^= 1;
                }
            }
            acc.iter().all(|&v| v == 0)
        })
        .expect("no root of q in F4 tower field");
    let mut power = vec![1];
    let cols: Vec<_> = (0..d)
        .map(|_| {
            let r = tbits(&power);
            power = rem4(&mul4(&power, &rho), &modulus);
            r
        })
        .collect();
    let rows: Vec<_> = (0..d)
        .map(|r| {
            cols.iter()
                .enumerate()
                .filter(|(_, c)| c.bit(r as u64))
                .fold(zero(), |a, (i, _)| a | bit(i))
        })
        .collect();
    let inv = left_inverse(&rows, d);
    let ra = reduction(q, na);
    let rb = reduction(q, nb);
    let ar: Vec<_> = rows.iter().map(|r| combine(r, &ra)).collect();
    let br: Vec<_> = rows.iter().map(|r| combine(r, &rb)).collect();
    let mut alg = Alg::default();
    let mut comp = Vec::new();
    for l in &gates4 {
        let (pa, ra) = form(l, &ar);
        let (pb, rb) = form(l, &br);
        let b = alg.gates.len();
        alg.gates.extend([
            (pa.clone(), pb.clone()),
            (ra.clone(), rb.clone()),
            (pa ^ ra, pb ^ rb),
        ]);
        comp.push((bit(b) | bit(b + 1), bit(b) | bit(b + 2)));
    }
    let mut out = vec![zero(); d];
    for k in 0..m {
        for g in 0..ng {
            let c = wm[k][g];
            let (g0, g1) = &comp[g];
            if c & 1 != 0 {
                out[2 * k] ^= g0;
                out[2 * k + 1] ^= g1;
            }
            if c & 2 != 0 {
                out[2 * k] ^= g1;
                out[2 * k + 1] ^= g0 ^ g1;
            }
        }
    }
    alg.w = inv.iter().map(|r| combine(r, &out)).collect();
    // The conversion above already precomposes the input reduction maps.
    (alg, reduction(q, na + nb - 1))
}
