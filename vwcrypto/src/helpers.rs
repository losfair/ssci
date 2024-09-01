use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::group::ff::PrimeField;
use poseidon_base::Hashable;

pub fn poseidon_hash_scheme(a: &[u8; 32], b: &[u8; 32], domain: &[u8; 32]) -> Option<[u8; 32]> {
    let fa = Fr::from_bytes(a);
    let fa = if fa.is_some().into() {
        fa.unwrap()
    } else {
        return None;
    };
    let fb = Fr::from_bytes(b);
    let fb = if fb.is_some().into() {
        fb.unwrap()
    } else {
        return None;
    };
    let fdomain = Fr::from_bytes(domain);
    let fdomain = if fdomain.is_some().into() {
        fdomain.unwrap()
    } else {
        return None;
    };
    Some(Fr::hash_with_domain([fa, fb], fdomain).to_repr())
}
