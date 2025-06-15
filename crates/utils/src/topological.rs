/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use std::{collections::VecDeque, hash::Hash};

#[derive(Debug)]
pub struct TopologicalSort<T: Copy + Eq + Hash> {
    edges: AHashMap<T, Vec<T>>,
    count: AHashMap<T, usize>,
}

impl<T: Copy + Eq + Hash + std::fmt::Debug> TopologicalSort<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            edges: AHashMap::with_capacity(capacity),
            count: AHashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, from: T, to: T) {
        self.count.entry(from).or_insert(0);
        self.edges.entry(from).or_default().push(to);
        *self.count.entry(to).or_insert(0) += 1;
    }

    pub fn into_iterator(mut self) -> TopologicalSortIterator<T> {
        let mut no_edges = VecDeque::with_capacity(self.count.len());
        self.count.retain(|node, count| {
            if *count == 0 {
                no_edges.push_back(*node);
                false
            } else {
                true
            }
        });

        TopologicalSortIterator {
            edges: self.edges,
            count: self.count,
            no_edges,
        }
    }
}

#[derive(Debug)]
pub struct TopologicalSortIterator<T: Copy + Eq + Hash> {
    edges: AHashMap<T, Vec<T>>,
    count: AHashMap<T, usize>,
    no_edges: VecDeque<T>,
}

impl<T: Copy + Eq + Hash> Iterator for TopologicalSortIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let no_edge = self.no_edges.pop_back()?;

        if let Some(edges) = self.edges.get(&no_edge) {
            for neighbor in edges {
                if let Some(count) = self.count.get_mut(neighbor) {
                    *count -= 1;
                    if *count == 0 {
                        self.count.remove(neighbor);
                        self.no_edges.push_front(*neighbor);
                    }
                }
            }
        }

        Some(no_edge)
    }
}

impl<T: Copy + Eq + Hash> TopologicalSortIterator<T> {
    pub fn is_valid(&self) -> bool {
        self.count.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topological_sort() {
        let mut sort = TopologicalSort::with_capacity(6);
        sort.insert(1, 2);
        sort.insert(1, 3);
        sort.insert(2, 4);
        sort.insert(3, 4);
        sort.insert(4, 5);
        sort.insert(5, 6);

        let mut iter = sort.into_iterator();
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.next(), None);
        assert!(iter.is_valid(), "{:?}", iter);
    }

    #[test]
    fn test_topological_sort_cycle() {
        let mut sort = TopologicalSort::with_capacity(6);
        sort.insert(1, 2);
        sort.insert(2, 3);
        sort.insert(3, 1);

        let mut iter = sort.into_iterator();
        assert_eq!(iter.next(), None);
        assert!(!iter.is_valid());
    }
}
