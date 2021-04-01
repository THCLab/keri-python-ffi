pub mod tel_event;
pub mod tel_manager;

use self::tel_event::{TelEvent, TelState};
use crate::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TEL {
    events: Vec<TelEvent>,
    state: TelState,
}

impl TEL {
    pub fn new() -> Self {
        TEL {
            events: vec![],
            state: TelState::NotIsuued,
        }
    }

    pub fn update(&self, event: TelEvent) -> Result<TEL, Error> {
        let state = event.apply(&self.state.clone())?;
        let mut events = self.events.clone();
        events.push(event);
        Ok(TEL { state, events })
    }

    pub fn get_state(&self) -> TelState {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {}
