//! Common utilities.

use crate::parse::Skeleton;

/// Strip the custom sections from the module.
pub fn strip<'a>(skeleton: &mut Skeleton<'a>) { skeleton.custom = Vec::new(); }
