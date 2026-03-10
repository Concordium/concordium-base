use crate::v1::trie::state_dump::shared::{Context, NodeId};
use crate::v1::trie::{LoadCallback, PersistentState};

pub mod shared;

pub(crate) fn dump_persistent_state(
    context: &mut Context,
    load_callback: LoadCallback,
    parent_node: NodeId,
    tree: &PersistentState,
) {
    println!("test");
    todo!()
}
