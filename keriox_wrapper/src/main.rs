use std::{
    error::Error,
    io::{self},
    thread,
};

use keriox_wrapper::entity::{SharedEntity};
use rand::{thread_rng, Rng};
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().to_str().unwrap();
    let ap_path = [".", "adr"].join("/");
    
    let mut rng = thread_rng();
    let port = rng.gen_range(1000, 9999);

    let ent_adr = ["localhost", &port.to_string()].join(":");

    let mut ent = SharedEntity::new(
        path, &ent_adr, // &seeds.trim(),
        &ap_path,
    )
    .unwrap();
    let ent1 = ent.clone();
    ent1.run()?;

    let command = thread::spawn(move || loop {
        let mut input = String::new();
        println!("Availabla commands:");
        match io::stdin().read_line(&mut input) {
            Ok(_n) => {
                let ii: Vec<_> = input.split(" ").collect();
                match ii[0].trim().as_ref() {
                    "rot" => {
                        println!("Rotate!");
                        {
                            ent.update_keys().unwrap();
                        }
                    }
                    "kel" => {
                        let kerl = ent.get_kerl().unwrap();
                        println!("KEL: \n{}", kerl);
                    }
                    "did" => {
                        let prefix = ii[1].trim();
                        {
                            let ddoc = ent.get_did_doc(prefix).unwrap();
                            println!("Got didoc:\n{}\n", ddoc);
                        }
                    }
                    _ => {}
                }
            }
            Err(error) => println!("error: {}", error),
        }
    });
    command.join().unwrap();

    Ok(())
}
