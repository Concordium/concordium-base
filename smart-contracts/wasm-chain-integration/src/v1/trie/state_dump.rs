use crate::v1::trie::state_dump::shared::{ NodeId, StateDumpBuilder};
use crate::v1::trie::{LoadCallback, PersistentState};

pub mod shared;

pub(crate) fn dump_persistent_state(
    builder: &mut StateDumpBuilder,
    load_callback: LoadCallback,
    parent_node: NodeId,
    tree: &PersistentState,
) {
    println!("test");
}
