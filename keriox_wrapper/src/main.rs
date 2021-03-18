use std::{
    error::Error,
    fs,
    io::{self},
    thread,
};

use keriox_wrapper::controller::SharedController;

use rand::{thread_rng, Rng};
use tempfile::{tempdir};

fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().to_str().unwrap();
    let ap_path = [".", "adr"].join("/");

    let mut rng = thread_rng();
    let port = rng.gen_range(1000, 9999);

    let ent_adr = ["localhost", &port.to_string()].join(":");

    let mut controller = SharedController::new(
        &ent_adr, // &seeds.trim(),
        &ap_path,
    )
    .unwrap();
    let ent1 = controller.clone();
    ent1.run()?;

    let command = thread::spawn(move || loop {
        let mut input = String::new();
        // println!("Availabla commands:");
        match io::stdin().read_line(&mut input) {
            Ok(_n) => {
                let ii: Vec<_> = input.split(" ").collect();
                match ii[0].trim().as_ref() {
                    "pre" => {
                        let p = controller.get_prefixes().unwrap();
                        println!("Prefixes: {:?}", p);
                    }
                    "new" => {
                        let mut rng = thread_rng();
                        let random_dir = rng.gen_range(1, 10000);
                        let p = random_dir.to_string();
                        let r = [".", &p].join("/");
                        fs::create_dir(r.clone()).unwrap();
                        controller.add_entity(&r);
                    }
                    "rot" => {
                        println!("Rotate!");
                        let prefix = ii[1].trim();
                        {
                            controller.update_keys(prefix).unwrap();
                        }
                    }
                    "kel" => {
                        let prefix = ii[1].trim();
                        let kerl = controller.get_kerl_of_prefix(prefix).unwrap();
                        println!("KEL: \n{}", kerl);
                    }
                    "did" => {
                        let prefix = ii[1].trim();
                        {
                            let ddoc = controller.get_did_doc(prefix).unwrap();
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
