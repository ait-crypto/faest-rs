mod alg;
pub mod poly;
mod search;
mod tower;
use poly::*;
use search::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

#[derive(Clone, Default)]
pub struct Alg {
    gates: Vec<(Poly, Poly)>,
    w: Vec<Poly>,
}

fn precompose(a: &Alg, ar: &[Poly], br: &[Poly]) -> Alg {
    Alg {
        gates: a
            .gates
            .iter()
            .map(|(f, g)| (combine(f, ar), combine(g, br)))
            .collect(),
        w: a.w.clone(),
    }
}

pub const PRESETS: [(&str, usize, usize, usize, usize); 8] = [
    ("128s", 128, 11, 7, 312),
    ("128f", 128, 17, 8, 312),
    ("192s", 192, 16, 12, 504),
    ("192f", 192, 24, 8, 504),
    ("256s", 256, 22, 6, 696),
    ("256f", 256, 33, 8, 704),
    ("em_192s", 192, 16, 8, 504),
    ("em_192f", 192, 25, 8, 504),
];

fn prune(f: &mut Vec<Poly>, g: &mut Vec<Poly>, wg: &mut Vec<Poly>) {
    let mut canon = BTreeMap::new();
    for i in 0..f.len() {
        if f[i] != zero() && g[i] != zero() {
            canon.entry((f[i].clone(), g[i].clone())).or_insert(i);
        }
    }
    let wg1: Vec<_> = wg
        .iter()
        .map(|r| {
            let mut nr = zero();
            for i in bits(r) {
                if f[i] != zero() && g[i] != zero() {
                    let j = canon[&(f[i].clone(), g[i].clone())];
                    nr ^= bit(j);
                }
            }
            nr
        })
        .collect();
    let used = wg1.iter().fold(zero(), |a, b| a | b);
    let mut newidx = BTreeMap::new();
    let mut f2 = Vec::new();
    let mut g2 = Vec::new();
    for i in bits(&used) {
        assert!(i < f.len(), "gate mask exceeds gate count");
        newidx.insert(i, f2.len());
        f2.push(f[i].clone());
        g2.push(g[i].clone());
    }
    *wg = wg1
        .iter()
        .map(|r| bits(r).fold(zero(), |a, i| a | bit(newidx[&i])))
        .collect();
    *f = f2;
    *g = g2;
}

fn emit_words(out: &mut String, name: &str, rows: &[Poly], width: usize) {
    let stride = width.div_ceil(64);
    writeln!(
        out,
        "pub(super) static {name}: [u64; {}] = [",
        rows.len() * stride
    )
    .unwrap();
    for row in rows {
        assert!(
            row.bits() as usize <= width,
            "{name}: row exceeds width {width}"
        );
        let words = row.to_u64_digits();
        for i in 0..stride {
            write!(out, "0x{:016x},", words.get(i).copied().unwrap_or(0)).unwrap();
        }
        out.push('\n');
    }
    out.push_str("];\n");
}

impl Generator {
    fn generate(
        &mut self,
        name: &str,
        lambda: usize,
        tau: usize,
        grind: usize,
        ngates: usize,
    ) -> String {
        let nb = lambda - grind;
        let n2 = lambda + nb - 1;
        let mut moduli = Vec::new();
        let d = nb / tau;
        let larger = nb % tau;
        for (degree, count) in [(d + 1, larger), (d, tau - larger)] {
            if count == 0 {
                continue;
            }
            let pool = self.irreducibles(degree);
            assert!(count <= pool.len(), "insufficient tree irreducibles");
            moduli.extend_from_slice(&pool[..count]);
        }
        assert_eq!(
            moduli.iter().map(degree).sum::<usize>(),
            nb,
            "tree degrees must sum to lambda - grinding bits"
        );
        let trees: BTreeSet<_> = moduli.iter().cloned().collect();
        let pools = (2..=10)
            .map(|d| {
                (
                    d,
                    self.irreducibles(d)
                        .into_iter()
                        .filter(|q| !trees.contains(q))
                        .collect(),
                )
            })
            .collect();
        let (_, picks) = self
            .search(lambda - 1, 10, 10, &pools)
            .expect("portfolio search failed");
        let mut evrows: Vec<_> = moduli.iter().flat_map(|m| reduction(m, n2)).collect();
        let mut gates = Vec::new();
        let mut masks = Vec::new();
        for p in picks {
            let (a, ev) = self.place_alg(&p, lambda, nb);
            let off = gates.len();
            gates.extend(a.gates);
            masks.extend(a.w.into_iter().map(|r| r << off));
            evrows.extend(ev);
        }
        let x = left_inverse(&evrows, n2);
        let red = reduction(&modulus(lambda), n2);
        let mut wt = vec![zero(); lambda];
        let mut wg = vec![zero(); lambda];
        for r in 0..lambda {
            let sel = combine(&red[r], &x);
            for i in bits(&sel) {
                if i < nb {
                    wt[r] |= bit(i);
                } else {
                    wg[r] ^= &masks[i - nb];
                }
            }
        }
        let cols = crt_cols(&moduli);
        let mut f = Vec::new();
        let mut g = Vec::new();
        for (fa, fb) in gates {
            f.push(fa);
            g.push(
                cols.iter()
                    .enumerate()
                    .filter(|(_, c)| parity(&(&fb & *c)))
                    .fold(zero(), |r, (j, _)| r | bit(j)),
            );
        }
        prune(&mut f, &mut g, &mut wg);
        assert_eq!(f.len(), ngates, "pruned gate count");
        let wc: Vec<_> = (0..lambda)
            .map(|r| {
                cols.iter()
                    .enumerate()
                    .filter(|(_, c)| c.bit(r as u64))
                    .fold(zero(), |a, (j, _)| a | bit(j))
            })
            .collect();
        let mut out = String::new();
        writeln!(out, "pub(super) mod p_{name} {{").unwrap();
        for (n, rows, width) in [
            ("F", &f, lambda),
            ("G", &g, nb),
            ("W_TREE", &wt, nb),
            ("W_GATE", &wg, ngates),
            ("W_CRT", &wc, nb),
        ] {
            emit_words(&mut out, n, rows, width);
        }
        writeln!(out, "pub(super) static TREE_MODULI: [u16; {tau}] = [").unwrap();
        for m in &moduli {
            assert!(degree(m) < 16, "tree modulus does not fit u16");
            write!(out, "0x{:04x},", m.to_u64_digits()[0]).unwrap();
        }
        out.push_str("];\n");
        emit_words(&mut out, "M_TREE", &[product(&moduli)], nb + 1);
        out.push_str("}\n");
        writeln!(out,"pub(crate) static TABLES_{}: VoleTables = VoleTables {{ name: {name:?}, lambda: {lambda}, tau: {tau}, grinding_bits: {grind}, gates: {ngates},",name.to_uppercase()).unwrap();
        for (field, n, rows, width) in [
            ("f", "F", ngates, lambda),
            ("g", "G", ngates, nb),
            ("w_tree", "W_TREE", lambda, nb),
            ("w_gate", "W_GATE", lambda, ngates),
            ("w_crt", "W_CRT", lambda, nb),
        ] {
            writeln!(out,"{field}: PackedMatrix {{ rows: {rows}, columns: {width}, stride: {}, words: &p_{name}::{n} }},",width.div_ceil(64)).unwrap();
        }
        writeln!(
            out,
            "tree_moduli: &p_{name}::TREE_MODULI, m_tree: &p_{name}::M_TREE, }};"
        )
        .unwrap();
        out
    }
}

pub fn generate_all() -> String {
    let mut generator = Generator::default();
    let mut output = String::from("// Generated by build/vole_tables; do not edit.\n");
    for (name, l, t, w, g) in PRESETS {
        // Retain the preset in diagnostics even for assertions deep in arithmetic/search.
        let generated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generator.generate(name, l, t, w, g)
        }))
        .unwrap_or_else(|e| {
            let msg = e
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("unknown invariant");
            panic!("VOLE preset {name}: {msg}");
        });
        output.push_str(&generated);
    }
    output
}
