use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("{{\"status\":\"error\",\"code\":\"authenticated-ipc-adapter-required\"}}");
    ExitCode::from(2)
}
