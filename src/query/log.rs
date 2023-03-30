use utils::codec::leb128::Leb128Iterator;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    Insert(u64),
    Update(u64),
    ChildUpdate(u64),
    Delete(u64),
}

pub struct Changes {
    pub changes: Vec<Change>,
    pub from_change_id: u64,
    pub to_change_id: u64,
}

#[derive(Debug)]
pub enum Query {
    All,
    Since(u64),
    SinceInclusive(u64),
    RangeInclusive(u64, u64),
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            changes: Vec::with_capacity(10),
            from_change_id: 0,
            to_change_id: 0,
        }
    }
}

impl Changes {
    pub fn deserialize(&mut self, bytes: &[u8]) -> Option<()> {
        let mut bytes_it = bytes.iter();
        let total_inserts: usize = bytes_it.next_leb128()?;
        let total_updates: usize = bytes_it.next_leb128()?;
        let total_child_updates: usize = bytes_it.next_leb128()?;
        let total_deletes: usize = bytes_it.next_leb128()?;

        if total_inserts > 0 {
            for _ in 0..total_inserts {
                self.changes.push(Change::Insert(bytes_it.next_leb128()?));
            }
        }

        if total_updates > 0 || total_child_updates > 0 {
            'update_outer: for change_pos in 0..(total_updates + total_child_updates) {
                let id = bytes_it.next_leb128()?;
                let mut is_child_update = change_pos >= total_updates;

                for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::Insert(insert_id) if *insert_id == id => {
                            // Item updated after inserted, no need to count this change.
                            continue 'update_outer;
                        }
                        Change::Update(update_id) if *update_id == id => {
                            // Move update to the front
                            is_child_update = false;
                            self.changes.remove(idx);
                            break;
                        }
                        Change::ChildUpdate(update_id) if *update_id == id => {
                            // Move update to the front
                            self.changes.remove(idx);
                            break;
                        }
                        _ => (),
                    }
                }

                self.changes.push(if !is_child_update {
                    Change::Update(id)
                } else {
                    Change::ChildUpdate(id)
                });
            }
        }

        if total_deletes > 0 {
            'delete_outer: for _ in 0..total_deletes {
                let id = bytes_it.next_leb128()?;

                'delete_inner: for (idx, change) in self.changes.iter().enumerate() {
                    match change {
                        Change::Insert(insert_id) if *insert_id == id => {
                            self.changes.remove(idx);
                            continue 'delete_outer;
                        }
                        Change::Update(update_id) | Change::ChildUpdate(update_id)
                            if *update_id == id =>
                        {
                            self.changes.remove(idx);
                            break 'delete_inner;
                        }
                        _ => (),
                    }
                }

                self.changes.push(Change::Delete(id));
            }
        }

        Some(())
    }
}
