// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{deserialized::Deserialized, error::IntegrityError, *};
use std::convert::TryFrom;

#[test]
fn insert_last() {
    let mut expected_keys = vec![];
    let (mut last_sk, pk) = gen_keypair();

    let mut chain = SecuredLinkedList::new(pk);
    expected_keys.push(pk);

    for _ in 0..10 {
        let last_pk = &expected_keys[expected_keys.len() - 1];
        let (sk, pk, sig) = gen_signed_keypair(&last_sk);

        assert_eq!(chain.insert(last_pk, pk, sig), Ok(()));

        expected_keys.push(pk);
        last_sk = sk;
    }

    assert_eq!(chain.keys().copied().collect::<Vec<_>>(), expected_keys);
}

#[test]
fn insert_fork() {
    let (sk0, pk0) = gen_keypair();
    let (sk1_a, pk1_a, sig1_a) = gen_signed_keypair(&sk0);
    let (_, pk2_a, sig2_a) = gen_signed_keypair(&sk1_a);
    let (_, pk1_b, sig1_b) = gen_signed_keypair(&sk0);

    let mut chain = SecuredLinkedList::new(pk0);
    assert_eq!(chain.insert(&pk0, pk1_a, sig1_a), Ok(()));
    assert_eq!(chain.insert(&pk1_a, pk2_a, sig2_a), Ok(()));
    assert_eq!(chain.insert(&pk0, pk1_b, sig1_b), Ok(()));

    let expected_keys = if pk1_a > pk1_b {
        vec![&pk0, &pk1_b, &pk1_a, &pk2_a]
    } else {
        vec![&pk0, &pk1_a, &pk1_b, &pk2_a]
    };

    let actual_keys: Vec<_> = chain.keys().collect();

    assert_eq!(actual_keys, expected_keys);
}

#[test]
fn insert_duplicate_key() {
    let (sk0, pk0) = gen_keypair();
    let (_, pk1, sig1) = gen_signed_keypair(&sk0);

    let mut chain = SecuredLinkedList::new(pk0);
    assert_eq!(chain.insert(&pk0, pk1, sig1.clone()), Ok(()));
    assert_eq!(chain.insert(&pk0, pk1, sig1), Ok(()));
    assert_eq!(chain.keys().collect::<Vec<_>>(), vec![&pk0, &pk1]);
}

#[test]
fn invalid_deserialized_chain_invalid_signature() {
    let (_, pk0) = gen_keypair();
    let (_, pk1) = gen_keypair();

    let bad_sk = bls::SecretKey::random();
    let bad_sig = sign(&bad_sk, &pk1);

    let src = Deserialized {
        root: pk0,
        tree: vec![Block {
            key: pk1,
            signature: bad_sig,
            parent_index: 0,
        }],
    };

    assert_eq!(
        SecuredLinkedList::try_from(src),
        Err(IntegrityError::FailedSignature)
    );
}

#[test]
fn invalid_deserialized_chain_wrong_parent_child_order() {
    // 0  2<-1<-+
    // |        |
    // +--------+

    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);

    let src = Deserialized {
        root: pk0,
        tree: vec![
            Block {
                key: pk2,
                signature: sig2,
                parent_index: 2,
            },
            Block {
                key: pk1,
                signature: sig1,
                parent_index: 0,
            },
        ],
    };

    assert_eq!(
        SecuredLinkedList::try_from(src),
        Err(IntegrityError::WrongBlockOrder)
    );
}

#[test]
fn invalid_deserialized_chain_wrong_sibling_order() {
    // 0->2 +->1
    // |    |
    // +----+

    let (sk0, pk0) = gen_keypair();

    let block1 = {
        let (_, key, signature) = gen_signed_keypair(&sk0);
        Block {
            key,
            signature,
            parent_index: 0,
        }
    };

    let block2 = {
        let (_, key, signature) = gen_signed_keypair(&sk0);
        Block {
            key,
            signature,
            parent_index: 0,
        }
    };

    let (small, large) = if block1 < block2 {
        (block1, block2)
    } else {
        (block2, block1)
    };

    let src = Deserialized {
        root: pk0,
        tree: vec![large, small],
    };

    assert_eq!(
        SecuredLinkedList::try_from(src),
        Err(IntegrityError::WrongBlockOrder)
    );
}

#[test]
fn invalid_deserialized_chain_wrong_unrelated_block_order() {
    // "unrelated" here means the blocks have neither parent-child relation, nor are they
    // siblings.

    // 0->1->2 +->3
    // |       |
    // +-------+

    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);
    let (_, pk3, sig3) = gen_signed_keypair(&sk0);

    let src = Deserialized {
        root: pk0,
        tree: vec![
            Block {
                key: pk1,
                signature: sig1,
                parent_index: 0,
            },
            Block {
                key: pk2,
                signature: sig2,
                parent_index: 1,
            },
            Block {
                key: pk3,
                signature: sig3,
                parent_index: 0,
            },
        ],
    };

    assert_eq!(
        SecuredLinkedList::try_from(src),
        Err(IntegrityError::WrongBlockOrder)
    );
}

#[test]
fn merge() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
    let (_, pk3, sig3) = gen_signed_keypair(&sk2);

    // lhs: 0->1->2
    // rhs: 2->3
    // out: 0->1->2->3
    let lhs = make_chain(
        pk0,
        vec![
            (&pk0, pk1, sig1.clone()),
            (&pk1, pk2, sig2.clone()),
            (&pk2, pk3, sig3.clone()),
        ],
    );
    let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3.clone())]);
    assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

    // lhs: 1->2->3
    // rhs: 0->1
    // out: 0->1->2->3
    let lhs = make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk2, pk3, sig3.clone())]);
    let rhs = make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]);
    assert_eq!(merge_chains(lhs, rhs), Ok(vec![pk0, pk1, pk2, pk3]));

    // lhs: 0->1
    // rhs: 2->3
    // out: Err(Incompatible)
    let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
    let rhs = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
    assert_eq!(merge_chains(lhs, rhs), Err(Error::InvalidOperation));
}

#[test]
fn merge_fork() {
    let (sk0, pk0) = gen_keypair();
    let (_, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk0);

    // rhs: 0->1
    // lhs: 0->2
    // out: Ok(0->1
    //         |
    //         +->2)
    let lhs = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
    let rhs = make_chain(pk0, vec![(&pk0, pk2, sig2)]);

    let expected = if pk1 < pk2 {
        vec![pk0, pk1, pk2]
    } else {
        vec![pk0, pk2, pk1]
    };

    assert_eq!(merge_chains(lhs, rhs), Ok(expected))
}

#[test]
fn minimize() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);

    let chain = make_chain(
        pk0,
        vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
    );

    assert_eq!(
        chain.minimize(iter::once(&pk0)),
        Ok(make_chain(pk0, vec![]))
    );
    assert_eq!(
        chain.minimize(iter::once(&pk1)),
        Ok(make_chain(pk1, vec![]))
    );
    assert_eq!(
        chain.minimize(iter::once(&pk2)),
        Ok(make_chain(pk2, vec![]))
    );

    assert_eq!(
        chain.minimize(vec![&pk0, &pk1]),
        Ok(make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]))
    );
    assert_eq!(
        chain.minimize(vec![&pk1, &pk2]),
        Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
    );
    assert_eq!(
        chain.minimize(vec![&pk0, &pk1, &pk2]),
        Ok(make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]))
    );

    let (_, bad_pk) = gen_keypair();
    assert_eq!(chain.minimize(iter::once(&bad_pk)), Err(Error::KeyNotFound));
}

#[test]
fn minimize_fork() {
    // 0->1->2->3
    //    |
    //    +->4
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
    let (_, pk3, sig3) = gen_signed_keypair(&sk2);

    // Test both cases (4 < 2 and 4 > 2):
    let k4_small = gen_signed_keypair_filter(&sk1, |pk| pk < &pk2);
    let k4_large = gen_signed_keypair_filter(&sk1, |pk| pk > &pk2);

    for (_, pk4, sig4) in vec![k4_small, k4_large] {
        let chain = make_chain(
            pk0,
            vec![
                (&pk0, pk1, sig1.clone()),
                (&pk1, pk2, sig2.clone()),
                (&pk2, pk3, sig3.clone()),
                (&pk1, pk4, sig4.clone()),
            ],
        );

        // 1->2->3
        // |
        // +->4
        assert_eq!(
            chain.minimize(vec![&pk3, &pk4]),
            Ok(make_chain(
                pk1,
                vec![
                    (&pk1, pk2, sig2.clone()),
                    (&pk2, pk3, sig3.clone()),
                    (&pk1, pk4, sig4)
                ]
            ))
        );
    }
}

// TODO:
// #[test]
// fn minimize_trims_unneeded_branches()

#[test]
fn truncate() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);

    let chain = make_chain(
        pk0,
        vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
    );

    assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
    assert_eq!(
        chain.truncate(2),
        make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
    );
    assert_eq!(
        chain.truncate(3),
        make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
    );

    // 0 is the same as 1
    assert_eq!(chain.truncate(0), make_chain(pk2, vec![]));
}

#[test]
fn trim_fork() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);
    let (_, pk3, sig3) = gen_signed_keypair(&sk1);

    let chain = make_chain(
        pk0,
        vec![
            (&pk0, pk1, sig1.clone()),
            (&pk1, pk2, sig2.clone()),
            (&pk1, pk3, sig3.clone()),
        ],
    );

    if pk2 < pk3 {
        assert_eq!(chain.truncate(1), make_chain(pk3, vec![]));
        assert_eq!(
            chain.truncate(2),
            make_chain(pk1, vec![(&pk1, pk3, sig3.clone())])
        );
        assert_eq!(
            chain.truncate(3),
            make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk3, sig3)])
        );
    } else {
        assert_eq!(chain.truncate(1), make_chain(pk2, vec![]));
        assert_eq!(
            chain.truncate(2),
            make_chain(pk1, vec![(&pk1, pk2, sig2.clone())])
        );
        assert_eq!(
            chain.truncate(3),
            make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)])
        );
    }
}

#[test]
fn extend() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);

    // 0->1->2
    let main_chain = make_chain(
        pk0,
        vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())],
    );

    // in:      2
    // trusted: 1
    // out:     1->2
    let chain = make_chain(pk2, vec![]);
    assert_eq!(
        chain.extend(&pk1, &main_chain),
        Ok(make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]))
    );

    // in:      2
    // trusted: 0
    // out:     0->1->2
    let chain = make_chain(pk2, vec![]);
    assert_eq!(
        chain.extend(&pk0, &main_chain),
        Ok(make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2.clone())]
        ))
    );

    // in:      1->2
    // trusted: 0
    // out:     0->1->2
    let chain = make_chain(pk1, vec![(&pk1, pk2, sig2.clone())]);
    assert_eq!(
        chain.extend(&pk0, &main_chain),
        Ok(make_chain(
            pk0,
            vec![(&pk0, pk1, sig1.clone()), (&pk1, pk2, sig2)]
        ))
    );

    // in:      2->3
    // trusted: 1
    // out:     Error
    let (_, pk3, sig3) = gen_signed_keypair(&sk2);
    let chain = make_chain(pk2, vec![(&pk2, pk3, sig3)]);
    assert_eq!(chain.extend(&pk1, &main_chain), Err(Error::KeyNotFound));

    // in:      2
    // trusted: 2
    // out:     2
    let chain = make_chain(pk2, vec![]);
    assert_eq!(chain.extend(&pk2, &main_chain), Ok(make_chain(pk2, vec![])));

    // in:      1
    // trusted: 0
    // out:     0->1
    let chain = make_chain(pk1, vec![]);
    assert_eq!(
        chain.extend(&pk0, &main_chain),
        Ok(make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]))
    );

    // in:      0->1
    // trusted: 2
    // out:     Error
    let chain = make_chain(pk0, vec![(&pk0, pk1, sig1)]);
    assert_eq!(
        chain.extend(&pk2, &main_chain),
        Err(Error::InvalidOperation)
    );

    // in:      X->Y->2 (forged chain)
    // trusted: 1
    // out:     Error
    let (skx, pkx) = gen_keypair();
    let (sky, pky, sigy) = gen_signed_keypair(&skx);
    let fake_sig2 = sign(&sky, &pk2);
    let chain = make_chain(pkx, vec![(&pkx, pky, sigy), (&pky, pk2, fake_sig2)]);
    assert_eq!(chain.extend(&pk1, &main_chain), Err(Error::KeyNotFound));
}

#[test]
fn extend_unreachable_trusted_key() {
    // main:    0->1->2->3
    //             |
    //             +->4
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (sk2, pk2, sig2) = gen_signed_keypair(&sk1);
    let (_, pk3, sig3) = gen_signed_keypair(&sk2);
    let (_, pk4, sig4) = gen_signed_keypair_filter(&sk1, |pk| pk > &pk2);

    let main_chain = make_chain(
        pk0,
        vec![
            (&pk0, pk1, sig1),
            (&pk1, pk2, sig2.clone()),
            (&pk2, pk3, sig3.clone()),
            (&pk1, pk4, sig4),
        ],
    );

    // in:      1->2->3
    // trusted: 4
    // out:     Error::InvalidOperation
    let chain = make_chain(pk1, vec![(&pk1, pk2, sig2), (&pk2, pk3, sig3)]);
    assert_eq!(
        chain.extend(&pk4, &main_chain),
        Err(Error::InvalidOperation)
    );
}

#[test]
fn cmp_by_position() {
    let (sk0, pk0) = gen_keypair();
    let (sk1, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk1);

    let main_chain = make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk1, pk2, sig2)]);

    assert_eq!(main_chain.cmp_by_position(&pk0, &pk1), Ordering::Less);
}

#[test]
fn main_branch_len() {
    let (sk0, pk0) = gen_keypair();
    let (_, pk1, sig1) = gen_signed_keypair(&sk0);
    let (_, pk2, sig2) = gen_signed_keypair(&sk0);

    // 0->1
    let chain = make_chain(pk0, vec![(&pk0, pk1, sig1.clone())]);
    assert_eq!(chain.main_branch_len(), 2);

    // 0->1
    // |
    // +->2
    let chain = make_chain(pk0, vec![(&pk0, pk1, sig1), (&pk0, pk2, sig2)]);
    assert_eq!(chain.main_branch_len(), 2);
}

fn gen_keypair() -> (bls::SecretKey, bls::PublicKey) {
    let sk = bls::SecretKey::random();
    let pk = sk.public_key();

    (sk, pk)
}

fn gen_signed_keypair(
    signing_sk: &bls::SecretKey,
) -> (bls::SecretKey, bls::PublicKey, bls::Signature) {
    let (sk, pk) = gen_keypair();
    let signature = sign(signing_sk, &pk);
    (sk, pk, signature)
}

// Generate a `(secret_key, public_key, signature)` tuple where `public_key` matches
// `predicate`.
fn gen_signed_keypair_filter<F>(
    signing_sk: &bls::SecretKey,
    predicate: F,
) -> (bls::SecretKey, bls::PublicKey, bls::Signature)
where
    F: Fn(&bls::PublicKey) -> bool,
{
    loop {
        let (sk, pk) = gen_keypair();
        if predicate(&pk) {
            let signature = sign(signing_sk, &pk);
            return (sk, pk, signature);
        }
    }
}

fn make_chain(
    root: bls::PublicKey,
    rest: Vec<(&bls::PublicKey, bls::PublicKey, bls::Signature)>,
) -> SecuredLinkedList {
    let mut chain = SecuredLinkedList::new(root);
    for (parent_key, key, signature) in rest {
        assert_eq!(chain.insert(parent_key, key, signature), Ok(()));
    }
    chain
}

// Merge `rhs` into `lhs`, verify the resulting chain is valid and return a vector of its keys.
fn merge_chains(
    mut lhs: SecuredLinkedList,
    rhs: SecuredLinkedList,
) -> Result<Vec<bls::PublicKey>, Error> {
    lhs.merge(rhs)?;
    Ok(lhs.keys().copied().collect())
}

fn sign(signing_sk: &bls::SecretKey, pk_to_sign: &bls::PublicKey) -> bls::Signature {
    bincode::serialize(pk_to_sign)
        .map(|bytes| signing_sk.sign(&bytes))
        .expect("failed to serialize public key")
}
