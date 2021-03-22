use std::{
    error::Error,
};

use keriox_wrapper::controller::SharedController;

use rand::{thread_rng, Rng};
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().to_str().unwrap();
    let ap_path = [path, "adr"].join("/");

    let mut rng = thread_rng();
    let port = rng.gen_range(1000, 9999);

    let ent_adr = ["localhost", &port.to_string()].join(":");

    let eve_controller = SharedController::new(
        &path, &ent_adr, // &seeds.trim(),
        &ap_path,
    )
    .unwrap();
    let eve = eve_controller.clone();
    eve_controller.run()?;

    let dir = tempdir()?;
    let path = dir.path().to_str().unwrap();

    let port = rng.gen_range(1000, 9999);

    let bob_adr = ["localhost", &port.to_string()].join(":");

    let bob_controller = SharedController::new(
        &path, &bob_adr, // &seeds.trim(),
        &ap_path,
    )
    .unwrap();
    let bob = bob_controller.clone();
    bob.run()?;
    let bob = bob_controller.clone();

    let ddoc = bob.get_did_doc(&eve.get_prefix()?)?;
    println!("eve's ddoc: {}", ddoc);

    let ddoc = eve.get_did_doc(&bob.get_prefix()?)?;
    println!("bob's ddoc: {}", ddoc);

    Ok(())
}
