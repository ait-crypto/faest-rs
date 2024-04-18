/*pub struct Tree {
    nodes: Vec<u8>,
    num_nodes: usize,
    num_leaves: usize,
}

fn node(tree : Tree, node: usize) -> u8 {
    tree.nodes[node]
}

fn is_left_child(node : usize) -> bool {
    (node != 0) & (node%2 == 1)
}

fn prg(k : vec<u8>, iv : u8, l : u32) -> vec<u8> {
    let mut res = k;
    res.append(k);
    return k;
}

fn commit<T>(r: T, iv: u8 , n: u32) -> () where T: fields::BigGalloisField, {
    let mut k = [[u8;(T::LENGTH as usize /8)]; n-1];
    k[0] = r.get_value().0.to_le_bytes().to_vec();
    k[0].append(r.get_value().1.to_le_bytes().to_vec());
    let mut max = 0;
    let log2n = u32::BITS - n.leading_zeros();
    for i in 0..2.pow(log2n)-1{
        let new_ks = prg(k[i], iv, T::LENGTH * 2);
        (k[(2*i)+1], k[(2*i)+2]) = (new_ks[..(T::LENGTH as usize /8)].to_vec(), new_ks[(T::LENGTH as usize /8)..].to_vec());
    }
    for j in 0..n
}

*/