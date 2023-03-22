use crate::{BM_TERM, TERM_EXACT};

use super::{
    Batch, BatchBuilder, HasFlag, IntoBitmap, IntoOperations, Operation, Serialize, Tokenize,
    F_CLEAR, F_INDEX, F_TOKENIZE, F_VALUE,
};

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            last_account_id: 0,
            last_document_id: 0,
            last_collection: 0,
        }
    }

    pub fn with_context(
        &mut self,
        account_id: u32,
        document_id: u32,
        collection: impl Into<u8>,
    ) -> &mut Self {
        self.last_account_id = account_id;
        self.last_document_id = document_id;
        self.last_collection = collection.into();
        self.push_context();
        self
    }

    #[inline(always)]
    pub(super) fn push_context(&mut self) {
        self.ops.push(Operation::WithContext {
            account_id: self.last_account_id,
            document_id: self.last_document_id,
            collection: self.last_collection,
        });
    }

    pub fn value(
        &mut self,
        field: impl Into<u8>,
        value: impl Serialize + Tokenize,
        options: u32,
    ) -> &mut Self {
        let field = field.into();
        let is_set = !options.has_flag(F_CLEAR);

        if options.has_flag(F_TOKENIZE) {
            for token in value.tokenize() {
                self.ops.push(Operation::Bitmap {
                    family: BM_TERM | TERM_EXACT,
                    field,
                    key: token,
                    set: is_set,
                });
            }
        }

        let value = value.serialize();

        if options.has_flag(F_INDEX) {
            self.ops.push(Operation::Index {
                field,
                key: value.clone(),
                set: is_set,
            });
        }

        if options.has_flag(F_VALUE) {
            self.ops.push(Operation::Value {
                field,
                set: if is_set { Some(value) } else { None },
            });
        }

        self
    }

    pub fn bitmap(&mut self, field: impl Into<u8>, value: impl IntoBitmap, options: u32) {
        let (key, family) = value.into_bitmap();
        self.ops.push(Operation::Bitmap {
            family,
            field: field.into(),
            key,
            set: !options.has_flag(F_CLEAR),
        });
    }

    pub fn acl(&mut self, to_account_id: u32, acl: Option<impl Serialize>) {
        self.ops.push(Operation::Acl {
            to_account_id,
            set: acl.map(|acl| acl.serialize()),
        })
    }

    pub fn blob(&mut self, blob_id: impl Serialize, options: u32) {
        self.ops.push(Operation::Blob {
            key: blob_id.serialize(),
            set: !options.has_flag(F_CLEAR),
        });
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> crate::Result<()> {
        value.build(self)
    }

    pub fn build(self) -> Batch {
        Batch { ops: self.ops }
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
