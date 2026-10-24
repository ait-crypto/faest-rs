use super::{Alg, poly::*};
use std::collections::BTreeMap;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Inf,
    Lin,
    Irr,
}

#[derive(Clone)]
pub struct Place {
    pub kind: Kind,
    pub poly: Poly,
    pub e: usize,
}

#[derive(Clone)]
pub enum Plan {
    Base,
    Mont5,
    Split(usize, usize),
    Crt(Vec<Place>),
    Full,
    ShortSplit(usize),
}

#[derive(Default)]
pub struct Generator {
    irreducibles: BTreeMap<usize, Vec<Poly>>,
    full_costs: BTreeMap<usize, (usize, Plan)>,
    short_costs: BTreeMap<usize, (usize, Plan)>,
    pub full_algs: BTreeMap<usize, Alg>,
    pub short_algs: BTreeMap<usize, Alg>,
}

pub fn tower_cost(d: usize) -> usize {
    match d {
        6 => 15,
        8 => 24,
        _ => 0,
    }
}

impl Generator {
    pub fn irreducibles(&mut self, d: usize) -> Vec<Poly> {
        self.irreducibles
            .entry(d)
            .or_insert_with(|| {
                ((1usize << d) | 1..1usize << (d + 1))
                    .map(|f| Poly::from(f))
                    .filter(irreducible)
                    .collect()
            })
            .clone()
    }

    pub fn place_cost(&mut self, p: &Place) -> usize {
        if p.kind != Kind::Irr {
            return self.short_cost(p.e).0;
        }
        let d = degree(&p.poly);
        let tc = tower_cost(d);
        if p.e == 1 && tc > 0 {
            tc.min(self.full_cost(d).0)
        } else {
            self.full_cost(d * p.e).0
        }
    }

    pub fn search(
        &mut self,
        target: usize,
        maxe: usize,
        cap: usize,
        pools: &BTreeMap<usize, Vec<Poly>>,
    ) -> Option<(usize, Vec<Place>)> {
        let mut groups: Vec<Vec<(usize, usize, Vec<Place>)>> = Vec::new();
        for (kind, poly) in [
            (Kind::Inf, zero()),
            (Kind::Lin, bit(1)),
            (Kind::Lin, Poly::from(3u8)),
        ] {
            let opts = (1..=maxe)
                .map(|e| {
                    (
                        e,
                        self.short_cost(e).0,
                        vec![Place {
                            kind,
                            poly: poly.clone(),
                            e,
                        }],
                    )
                })
                .collect::<Vec<_>>();
            if !opts.is_empty() {
                groups.push(opts);
            }
        }
        for (&d, pool) in pools {
            if pool.is_empty() {
                continue;
            }
            let mut opts = Vec::new();
            if d == 2 {
                for e in 1..=cap / d {
                    let p = Place {
                        kind: Kind::Irr,
                        poly: pool[0].clone(),
                        e,
                    };
                    opts.push((d * e, self.place_cost(&p), vec![p]));
                }
            } else {
                let per = self.place_cost(&Place {
                    kind: Kind::Irr,
                    poly: pool[0].clone(),
                    e: 1,
                });
                for t in 1..=pool.len().min(target / d + 1) {
                    opts.push((
                        t * d,
                        t * per,
                        pool[..t]
                            .iter()
                            .map(|p| Place {
                                kind: Kind::Irr,
                                poly: p.clone(),
                                e: 1,
                            })
                            .collect(),
                    ));
                }
            }
            if !opts.is_empty() {
                groups.push(opts);
            }
        }
        let mut dp = BTreeMap::from([(0, (0, Vec::new()))]);
        for opts in groups {
            let mut ndp = dp.clone();
            for (&d, (cost, picks)) in &dp {
                for (od, oc, op) in &opts {
                    let nd = target.min(d + od);
                    let nc = cost + oc;
                    if ndp.get(&nd).is_none_or(|(c, _)| nc < *c) {
                        let mut ps = picks.clone();
                        ps.extend_from_slice(op);
                        ndp.insert(nd, (nc, ps));
                    }
                }
            }
            dp = ndp;
        }
        dp.remove(&target)
    }

    pub fn full_cost(&mut self, n: usize) -> (usize, Plan) {
        if let Some(p) = self.full_costs.get(&n) {
            return p.clone();
        }
        let mut best = if n == 1 {
            Some((1, Plan::Base))
        } else if n == 5 {
            Some((13, Plan::Mont5))
        } else {
            None
        };
        if n != 1 {
            for s in 2..n {
                let m = n.div_ceil(s);
                let c = self.full_cost(s).0 * self.full_cost(m).0;
                if best.as_ref().is_none_or(|(b, _)| c < *b) {
                    best = Some((c, Plan::Split(s, m)));
                }
            }
            let pools = (2..n).map(|d| (d, self.irreducibles(d))).collect();
            if let Some((c, p)) = self.search(2 * n - 1, n - 1, n - 1, &pools) {
                if best.as_ref().is_none_or(|(b, _)| c < *b) {
                    best = Some((c, Plan::Crt(p)));
                }
            }
        }
        let best = best.expect("full_cost failed");
        self.full_costs.insert(n, best.clone());
        best
    }

    pub fn short_cost(&mut self, n: usize) -> (usize, Plan) {
        if let Some(p) = self.short_costs.get(&n) {
            return p.clone();
        }
        let mut best = if n == 1 {
            (1, Plan::Base)
        } else {
            (self.full_cost(n).0, Plan::Full)
        };
        if n != 1 {
            for m in n.div_ceil(2)..n {
                let c = self.full_cost(m).0 + 2 * self.short_cost(n - m).0;
                if c < best.0 {
                    best = (c, Plan::ShortSplit(m));
                }
            }
        }
        self.short_costs.insert(n, best.clone());
        best
    }
}
