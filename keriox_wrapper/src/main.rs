use std::error::Error;

use clap::App as clapapp;
use clap::Arg;
use keriox_wrapper::entity::Entity;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clapapp::new("get-command-line-args")
        .arg(
            Arg::with_name("host")
                .short('H'.to_string())
                .help("hostname on which we would listen, default: localhost")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short('P'.to_string())
                .help("port on which we would open TCP connections, default: 5621")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("client")
                .short('C'.to_string())
                .help("run client")
                .takes_value(false),
        )
        .get_matches();

    let host = matches.value_of("host").unwrap_or("localhost");
    let port = matches.value_of("port").unwrap_or("5621");
    let _address = [host, ":", port].concat();

    let addr_dir = tempdir()?;
    let ap_path = addr_dir.path().to_str().unwrap();

    if matches.is_present("client") {
        let dir = tempdir()?;
        let path = dir.path().to_str().unwrap();
        let seeds = "[
                \"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\",
                \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\"
                ]";
        let ent_adr = "localhost:3333";
        let mut ent = Entity::new_from_seeds(path, ent_adr, &seeds.trim(), ap_path)?;

        println!("\n{}\n", ent.get_did_doc(&ent.get_prefix()?)?);
        ent.update_keys()?;
        println!("\n{}\n", ent.get_did_doc(&ent.get_prefix()?)?);

        let eve_id = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";

        println!("\ndidioc: {}\n", ent.get_did_doc(eve_id,)?);

        println!(
            "==========================\ndidioc: {}\n",
            ent.get_did_doc("DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8",)?
        );
    } else {
        let dir2 = tempdir()?;
        let path = dir2.path().to_str().unwrap();
        let seeds = "[
                \"cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=\",
                \"lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=\"
            ]";
        let eve_adr = "localhost:2222";
        let ent = Entity::new_from_seeds(path, eve_adr, &seeds.trim(), ap_path)?;
        println!("{}", ent.get_prefix()?);
        ent.run()?;
    }
    Ok(())
}
