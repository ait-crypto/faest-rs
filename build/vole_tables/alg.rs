// SPDX-License-Identifier: MIT
use super::{Alg, poly::*, precompose, search::*, tower};

fn base() -> Alg {
    Alg {
        gates: vec![(one(), one())],
        w: vec![one()],
    }
}

fn mont5() -> Alg {
    let gates = [31u8, 29, 23, 27, 13, 22, 24, 3, 17, 16, 8, 2, 1]
        .into_iter()
        .map(|m| (Poly::from(m), Poly::from(m)))
        .collect();
    let w: &[&[usize]] = &[
        &[12],
        &[7, 11, 12],
        &[2, 5, 7, 8, 9, 12],
        &[0, 1, 3, 6, 8, 9],
        &[0, 4, 5, 6, 7, 9, 10, 11, 12],
        &[0, 2, 3, 7, 8, 12],
        &[1, 4, 6, 8, 9, 12],
        &[6, 9, 10],
        &[9],
    ];
    Alg {
        gates,
        w: w.iter()
            .map(|r| r.iter().fold(zero(), |a, &i| a | bit(i)))
            .collect(),
    }
}

impl Generator {
    pub fn full_alg(&mut self, n: usize) -> Alg {
        if let Some(a) = self.full_algs.get(&n) {
            return a.clone();
        }
        let alg = match self.full_cost(n).1 {
            Plan::Base => base(),
            Plan::Mont5 => mont5(),
            Plan::Split(s, m) => {
                let oa = self.full_alg(s);
                let ia = self.full_alg(m);
                let ng = ia.gates.len();
                let mut gates = Vec::new();
                for (fo, go) in &oa.gates {
                    let forms = |f: &Poly| {
                        (0..m)
                            .map(|i| {
                                bits(f)
                                    .filter(|&t| t * m + i < n)
                                    .fold(zero(), |r, t| r | bit(t * m + i))
                            })
                            .collect::<Vec<_>>()
                    };
                    let ar = forms(fo);
                    let br = forms(go);
                    gates.extend(
                        ia.gates
                            .iter()
                            .map(|(f, g)| (combine(f, &ar), combine(g, &br))),
                    );
                }
                let w = (0..2 * n - 1)
                    .map(|q| {
                        let mut row = zero();
                        for r in 0..2 * s - 1 {
                            if r * m <= q && q - r * m <= 2 * m - 2 {
                                for o in bits(&oa.w[r]) {
                                    row ^= &ia.w[q - r * m] << (o * ng);
                                }
                            }
                        }
                        row
                    })
                    .collect();
                Alg { gates, w }
            }
            Plan::Crt(picks) => {
                let mut gates = Vec::new();
                let mut masks = Vec::new();
                let mut evrows = Vec::new();
                for p in picks {
                    let (a, ev) = self.place_alg(&p, n, n);
                    let off = gates.len();
                    gates.extend(a.gates);
                    masks.extend(a.w.into_iter().map(|r| r << off));
                    evrows.extend(ev);
                }
                let inv = left_inverse(&evrows, 2 * n - 1);
                let w = inv.iter().map(|r| combine(r, &masks)).collect();
                Alg { gates, w }
            }
            _ => panic!("invalid full plan"),
        };
        self.full_algs.insert(n, alg.clone());
        alg
    }

    pub fn short_alg(&mut self, n: usize) -> Alg {
        if let Some(a) = self.short_algs.get(&n) {
            return a.clone();
        }
        let alg = match self.short_cost(n).1 {
            Plan::Base => base(),
            Plan::Full => self.full_alg(n),
            Plan::ShortSplit(m) => {
                let lo: Vec<_> = (0..m).map(bit).collect();
                let g1 = precompose(&self.full_alg(m), &lo, &lo);
                let s = self.short_alg(n - m);
                let lo: Vec<_> = (0..n - m).map(bit).collect();
                let hi: Vec<_> = (m..n).map(bit).collect();
                let g2 = precompose(&s, &lo, &hi);
                let g3 = precompose(&s, &hi, &lo);
                let o2 = g1.gates.len();
                let o3 = o2 + g2.gates.len();
                let w = (0..n)
                    .map(|j| {
                        let mut r = zero();
                        if j <= 2 * m - 2 {
                            r ^= &g1.w[j];
                        }
                        if j >= m {
                            r ^= (&g2.w[j - m] << o2) ^ (&g3.w[j - m] << o3);
                        }
                        r
                    })
                    .collect();
                let mut gates = g1.gates;
                gates.extend(g2.gates);
                gates.extend(g3.gates);
                Alg { gates, w }
            }
            _ => panic!("invalid short plan"),
        };
        self.short_algs.insert(n, alg.clone());
        alg
    }

    pub fn place_alg(&mut self, p: &Place, na: usize, nb: usize) -> (Alg, Vec<Poly>) {
        let n2 = na + nb - 1;
        if p.kind == Kind::Inf {
            assert!(
                p.e <= na.min(nb),
                "infinity multiplicity exceeds input width"
            );
            let ar: Vec<_> = (0..p.e).map(|i| bit(na - 1 - i)).collect();
            let br: Vec<_> = (0..p.e).map(|i| bit(nb - 1 - i)).collect();
            return (
                precompose(&self.short_alg(p.e), &ar, &br),
                (0..p.e).map(|i| bit(n2 - 1 - i)).collect(),
            );
        }
        let q = pow(&p.poly, p.e);
        let ra = reduction(&q, na);
        let rb = reduction(&q, nb);
        let ev = reduction(&q, n2);
        if p.kind == Kind::Lin {
            if p.poly == bit(1) {
                return (precompose(&self.short_alg(p.e), &ra, &rb), ev);
            }
            let pascal: Vec<_> = (0..p.e)
                .map(|i| {
                    (i..p.e)
                        .filter(|&j| i & j == i)
                        .fold(zero(), |r, j| r | bit(j))
                })
                .collect();
            let transform =
                |rows: &[Poly]| pascal.iter().map(|r| combine(r, rows)).collect::<Vec<_>>();
            return (
                precompose(&self.short_alg(p.e), &transform(&ra), &transform(&rb)),
                transform(&ev),
            );
        }
        let d = degree(&p.poly);
        let tc = tower_cost(d);
        if p.e == 1 && tc > 0 && tc < self.full_cost(d).0 {
            return tower::tower(&p.poly, na, nb);
        }
        let d = degree(&q);
        let mut a = precompose(&self.full_alg(d), &ra, &rb);
        a.w = reduction(&q, 2 * d - 1)
            .iter()
            .map(|r| combine(r, &a.w))
            .collect();
        (a, ev)
    }
}
