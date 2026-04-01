use crate::v1::trie::low_level::{CachedRef, Chunk};
use crate::v1::trie::state_dump::shared::{NodeId, StateDumpBuilder};
use crate::v1::trie::{
    Hashed, LoadCallback, Node, PersistentState, PersistentStateImpl, Reference,
};

pub mod shared;

pub fn dump_persistent_state(
    builder: &mut StateDumpBuilder,
    mut load_callback: LoadCallback,
    parent_node: NodeId,
    tree: &PersistentState,
) {
    let blob_reference = tree
        .blob_ref
        .expect("blob reference not set on PersistentState");

    let hash = tree.hash(&mut load_callback);

    let empty = matches!(&tree.inner, PersistentStateImpl::Empty);

    let graph_node_option = builder.build_blob_ref_node(
        parent_node,
        "trie",
        &format!("trie{{empty={}}}", empty),
        blob_reference,
        Some(hash),
    );

    if let Some(graph_node) = graph_node_option {
        match &tree.inner {
            PersistentStateImpl::Empty => {}
            PersistentStateImpl::Root(node_ref) => {
                dump_node_rec(
                    builder,
                    &mut load_callback,
                    graph_node,
                    None,
                    "".to_string(),
                    node_ref,
                );
            }
        }
    }
}

fn dump_node_rec(
    builder: &mut StateDumpBuilder,
    load_callback: &mut LoadCallback,
    parent_node: NodeId,
    child_link_nibble: Option<Chunk<4>>,
    key_prefix: String,
    node_ref: &CachedRef<Hashed<Node>>,
) {
    let reference = get_cached_ref_reference(node_ref);

    let node = node_ref.get(load_callback).make_owned();

    let stem_hex_full = child_link_nibble
        .map(|chunk| format!("{:01.1x}", chunk.value))
        .into_iter()
        .chain(node.data.path.data.iter().map(|b| format!("{:02x}", b)))
        .collect::<String>();

    let stem_hex = if node.data.path.last_partial {
        let mut stem_hex = stem_hex_full;
        stem_hex.pop();
        stem_hex
    } else {
        stem_hex_full
    };

    let stem_display = if stem_hex.len() > 6 {
        format!("{:.6}..", stem_hex)
    } else {
        stem_hex.clone()
    };

    let graph_node_option = builder.build_blob_ref_node(
        parent_node,
        &stem_display,
        &format!("node{{value={}}}", node.data.value.is_some()),
        reference,
        Some(node.hash),
    );

    let key = format!("{}{}", key_prefix, stem_hex);

    if let Some(graph_node) = graph_node_option {
        let value = if let Some(value_link) = node.data.value.as_ref() {
            let value = value_link.borrow();
            let value = value.get(load_callback);
            Some(value.to_vec())
        } else {
            None
        };

        let value_display = value.map(|value| {
            value
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        });

        builder.build_state_data(
            reference,
            node.hash,
            TrieNode {
                stem: stem_hex,
                key: key.clone(),
                value: value_display,
            },
        );

        for child_link in &node.data.children {
            let child_ref = child_link.1.borrow();
            dump_node_rec(
                builder,
                load_callback,
                graph_node,
                Some(child_link.0),
                key.clone(),
                &*child_ref,
            );
        }
    }
}

#[derive(Debug)]
struct TrieNode {
    stem: String,
    key: String,
    value: Option<String>,
}

fn get_cached_ref_reference<V>(r: &CachedRef<V>) -> Reference {
    match r {
        CachedRef::Disk { reference } => *reference,
        CachedRef::Memory { .. } => panic!("CachedRef::Memory variant unexpected"),
        CachedRef::Cached { reference, .. } => *reference,
    }
}
