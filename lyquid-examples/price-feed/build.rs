use std::{
    env,
    path::Path,
    process::{Command, Stdio},
};

fn command_succeeds(command: &mut Command) -> bool {
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn pnpm_command(ui_dir: &Path) -> Command {
    let mut pnpm = Command::new("pnpm");
    pnpm.arg("--version");
    if command_succeeds(&mut pnpm) {
        Command::new("pnpm")
    } else {
        let mut corepack = Command::new("corepack");
        corepack.args(["pnpm", "--version"]).current_dir(ui_dir);
        assert!(
            command_succeeds(&mut corepack),
            "Price Feed requires pnpm or Corepack to build its hosted UI. Install Node.js with Corepack enabled, then rerun the build."
        );

        let mut command = Command::new("corepack");
        command.arg("pnpm");
        command
    }
}

fn run_pnpm(ui_dir: &Path, arguments: &[&str]) {
    let status = pnpm_command(ui_dir)
        .args(arguments)
        .current_dir(ui_dir)
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "Price Feed requires pnpm or Corepack to build its hosted UI. Install Node.js with Corepack enabled, then rerun the build: {error}"
            )
        });

    assert!(
        status.success(),
        "Price Feed UI command failed: pnpm {}",
        arguments.join(" ")
    );
}

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
    let ui_dir = Path::new(&manifest_dir).join("ui");

    for path in [
        "build.rs",
        "ui/package.json",
        "ui/pnpm-lock.yaml",
        "ui/tsconfig.json",
        "ui/tsconfig.app.json",
        "ui/tsconfig.node.json",
        "ui/vite.config.ts",
        "ui/src",
        "ui/public",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    run_pnpm(&ui_dir, &["install", "--frozen-lockfile"]);
    run_pnpm(&ui_dir, &["build"]);
}
