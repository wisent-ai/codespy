use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

static NEXT_CASE: AtomicUsize = AtomicUsize::new(0);

pub struct Journey {
    pub root: PathBuf,
    pub inputs: PathBuf,
    next_run: usize,
}

impl Journey {
    pub fn new(name: &str) -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
        let evidence = repository.join("target/scan-policy");
        fs::create_dir_all(&evidence).unwrap();
        let root = loop {
            let id = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
            let root = evidence.join(format!("{name}-{}-{id}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create {}: {error}", root.display()),
            }
        };
        let inputs = root.join("inputs");
        fs::create_dir(&inputs).unwrap();
        for (name, args) in [
            ("source-revision.txt", vec!["rev-parse", "HEAD"]),
            ("source-diff.patch", vec!["diff", "--binary", "HEAD"]),
            ("source-status.txt", vec!["status", "--porcelain", "--untracked-files=all"]),
        ] {
            let output = Command::new("git").args(args).current_dir(repository).output().unwrap();
            assert!(output.status.success(), "cannot record source identity: {output:?}");
            fs::write(root.join(name), output.stdout).unwrap();
        }
        Self { root, inputs, next_run: 0 }
    }

    pub fn source(&self, name: &str, text: &str) -> PathBuf {
        let file = self.inputs.join(name);
        fs::write(&file, text).unwrap();
        file
    }

    pub fn policy(&self, value: &Value) -> PathBuf {
        let file = self.root.join("policy.json");
        fs::write(&file, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        file
    }

    pub fn run(&mut self, input: &Path, format: &str, policy: Option<&Path>) -> (Output, PathBuf) {
        let run = self.root.join(format!("run-{}", self.next_run));
        self.next_run += 1;
        fs::create_dir(&run).unwrap();
        let report = run.join("report.txt");
        let binary = env!("CARGO_BIN_EXE_codespy");
        let mut command = Command::new(binary);
        command.arg(input).args(["--format", format, "--no-color", "--output"]).arg(&report);
        if let Some(policy) = policy {
            command.arg("--scoring-policy").arg(policy);
            if let Ok(contents) = fs::read(policy) {
                fs::write(run.join("policy.json"), contents).unwrap();
            }
        }
        let arguments: Vec<_> = command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        let output = command.output().unwrap();
        fs::write(run.join("stdout.txt"), &output.stdout).unwrap();
        fs::write(run.join("stderr.txt"), &output.stderr).unwrap();
        fs::write(run.join("command.json"), serde_json::to_vec_pretty(&json!({
            "binary": binary,
            "arguments": arguments,
            "exit_status": output.status.code(),
            "success": output.status.success(),
        })).unwrap()).unwrap();
        (output, report)
    }
}

impl Drop for Journey {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.inputs).expect("remove isolated scan inputs, retain reports");
    }
}

pub fn policy() -> Value {
    json!({
        "top_score": 20,
        "lines_per_size_unit": 1,
        "leniency_per_size_unit": 0,
        "minimum_size_factor": 0,
        "deductions": {"critical": 10, "high": 4, "medium": 2, "low": 1, "info": 0},
        "grades": [{"floor": 16, "label": "review"}, {"floor": 0, "label": "investigate"}]
    })
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
