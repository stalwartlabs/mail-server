use crate::BM_DOCUMENT_IDS;

use super::{
    Batch, BatchBuilder, HasFlag, IntoBitmap, IntoOperations, Operation, Serialize, Tokenize,
    F_CLEAR, F_INDEX, F_TOKENIZE, F_VALUE,
};

impl BatchBuilder {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn with_account_id(&mut self, account_id: u32) -> &mut Self {
        self.ops.push(Operation::AccountId { account_id });
        self
    }

    pub fn with_collection(&mut self, collection: impl Into<u8>) -> &mut Self {
        self.ops.push(Operation::Collection {
            collection: collection.into(),
        });
        self
    }

    pub fn create_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });

        // Remove reserved id
        self.ops.push(Operation::Index {
            field: u8::MAX,
            key: vec![],
            set: false,
        });

        // Add document id
        self.ops.push(Operation::Bitmap {
            family: BM_DOCUMENT_IDS,
            field: u8::MAX,
            key: vec![],
            set: true,
        });
        self
    }

    pub fn update_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self
    }

    pub fn delete_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.ops.push(Operation::Bitmap {
            family: BM_DOCUMENT_IDS,
            field: u8::MAX,
            key: vec![],
            set: false,
        });
        self
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
            value.tokenize(&mut self.ops, field, is_set);
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
                family: 0,
                set: if is_set { Some(value) } else { None },
            });
        }

        self
    }

    pub fn bitmap(
        &mut self,
        field: impl Into<u8>,
        value: impl IntoBitmap,
        options: u32,
    ) -> &mut Self {
        let (key, family) = value.into_bitmap();
        self.ops.push(Operation::Bitmap {
            family,
            field: field.into(),
            key,
            set: !options.has_flag(F_CLEAR),
        });
        self
    }

    pub fn acl(&mut self, grant_account_id: u32, acl: Option<impl Serialize>) -> &mut Self {
        self.ops.push(Operation::Acl {
            grant_account_id,
            set: acl.map(|acl| acl.serialize()),
        });
        self
    }

    pub fn blob(&mut self, blob_id: impl Serialize, options: u32) -> &mut Self {
        self.ops.push(Operation::Blob {
            key: blob_id.serialize(),
            set: !options.has_flag(F_CLEAR),
        });
        self
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> crate::Result<()> {
        value.build(self)
    }

    pub fn build(self) -> Batch {
        Batch { ops: self.ops }
    }

    pub fn build_batch(&mut self) -> Batch {
        Batch {
            ops: std::mem::take(&mut self.ops),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
