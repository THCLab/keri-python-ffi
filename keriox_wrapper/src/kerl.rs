use crate::error::Error;
use keri::{
    database::lmdb::LmdbEventDatabase,
    event_message::parse::signed_event_stream,
    prefix::{IdentifierPrefix},
    processor::EventProcessor,
    state::IdentifierState,
};
use std::path::Path;

pub struct Kerl {
    processor: EventProcessor<LmdbEventDatabase>,
}

impl Kerl {
    pub fn new(db_path: &str) -> Result<Self, Error> {
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let processor = EventProcessor::new(db);

        let out = Self { processor };
        Ok(out)
    }

    pub fn get_kerl(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.processor
            .get_kerl(&id)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn process_events(&self, kel: &[u8]) -> Result<(), Error> {
        let events = signed_event_stream(kel).map_err(|e| Error::Generic(e.to_string()))?;
        for event in events.1 {
            self.processor.process(event)?;
        }

        Ok(())
    }

    pub fn get_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        self.processor
            .compute_state(&id)
            .map_err(|e| Error::Generic(e.to_string()))
    }
}
