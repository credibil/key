use std::collections::HashMap;

use credibil_did::webvh::DidLog;

#[derive(Clone, Debug)]
pub struct Log {
    entries: HashMap<String, DidLog>,
}

impl Log {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn add_log(&mut self, id: impl Into<String>, entry: DidLog) -> anyhow::Result<()> {
        self.entries.insert(id.into(), entry);
        Ok(())
    }

    pub fn get_log(&self, id: impl Into<String>) -> Option<DidLog> {
        self.entries.get(&id.into()).cloned()
    }
}
