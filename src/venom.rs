/// Build an `msfvenom` argv. Does not generate payload bytes.
#[derive(Clone, Debug)]
pub struct VenomSpec {
    pub payload: String,
    pub lhost: String,
    pub lport: String,
    pub format: String,
    pub encoder: String,
    pub iterations: u32,
    pub outfile: String,
    pub extra: String,
}

impl Default for VenomSpec {
    fn default() -> Self {
        Self {
            payload: "windows/x64/meterpreter/reverse_tcp".into(),
            lhost: "127.0.0.1".into(),
            lport: "4444".into(),
            format: "exe".into(),
            encoder: String::new(),
            iterations: 1,
            outfile: "payload.bin".into(),
            extra: String::new(),
        }
    }
}

impl VenomSpec {
    pub fn argv(&self) -> Vec<String> {
        let mut a = vec![
            "msfvenom".into(),
            "-p".into(),
            self.payload.clone(),
            format!("LHOST={}", self.lhost),
            format!("LPORT={}", self.lport),
            "-f".into(),
            self.format.clone(),
        ];
        if !self.encoder.is_empty() {
            a.push("-e".into());
            a.push(self.encoder.clone());
            if self.iterations > 1 {
                a.push("-i".into());
                a.push(self.iterations.to_string());
            }
        }
        if !self.outfile.is_empty() {
            a.push("-o".into());
            a.push(self.outfile.clone());
        }
        if !self.extra.is_empty() {
            a.extend(self.extra.split_whitespace().map(|s| s.to_string()));
        }
        a
    }

    pub fn preview(&self) -> String {
        self.argv().join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_basic() {
        let v = VenomSpec::default();
        let a = v.argv();
        assert_eq!(a[0], "msfvenom");
        assert!(a.contains(&"LHOST=127.0.0.1".into()));
        assert!(a.contains(&"LPORT=4444".into()));
        assert!(!a.contains(&"LHOST".into()));
        assert!(a.contains(&"-p".into()));
        assert!(a.contains(&"windows/x64/meterpreter/reverse_tcp".into()));
        assert!(a.contains(&"-o".into()));
    }

    #[test]
    fn argv_encoder() {
        let mut v = VenomSpec::default();
        v.encoder = "x86/shikata_ga_nai".into();
        v.iterations = 3;
        let p = v.preview();
        assert!(p.contains("-e x86/shikata_ga_nai"));
        assert!(p.contains("-i 3"));
    }
}

/// Capture subprocess output so generation cannot overwrite the active terminal.
#[cfg(test)]
pub async fn generate(argv: &[String]) -> (String, String) {
    let (_tx, rx) = tokio::sync::watch::channel(false);
    generate_cancellable(argv, rx).await
}

pub async fn generate_cancellable(
    argv: &[String],
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> (String, String) {
    let Some(program) = argv.first() else {
        return ("failed".into(), "empty payload command".into());
    };
    if *cancel.borrow() {
        return ("cancelled".into(), "payload generation cancelled".into());
    }
    let mut command = tokio::process::Command::new(program);
    command
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::select! {output=command.output()=>output,_=cancel.changed()=>return("cancelled".into(),"payload generation cancelled; generator terminated".into())};
    match output {
        Ok(output) => {
            let status = if output.status.success() {
                "complete"
            } else {
                "failed"
            };
            // Payload bytes can appear on stdout when no output file is chosen.
            let detail = format!(
                "{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            (status.into(), detail)
        }
        Err(error) => ("failed".into(), error.to_string()),
    }
}

#[cfg(test)]
mod execution_tests {
    #[tokio::test]
    async fn payload_subprocess_reports_success_failure_and_spawn_errors() {
        // Mock programs only; no payload is generated.
        let ok = super::generate(&[
            "sh".into(),
            "-c".into(),
            "printf bytes; printf saved >&2".into(),
        ])
        .await;
        assert_eq!(ok.0, "complete");
        assert!(ok.1.contains("saved"));
        assert!(!ok.1.contains("bytes"));
        let failed = super::generate(&[
            "sh".into(),
            "-c".into(),
            "printf invalid >&2; exit 7".into(),
        ])
        .await;
        assert_eq!(failed.0, "failed");
        assert!(failed.1.contains("invalid"));
        assert_eq!(
            super::generate(&["/does/not/exist".into()]).await.0,
            "failed"
        );
    }
    #[tokio::test]
    async fn payload_cancellation_terminates_the_mock_generator() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let argv = vec![
            "sh".into(),
            "-c".into(),
            format!("echo $$ > '{}'; exec sleep 10", pidfile.display()),
        ];
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move { super::generate_cancellable(&argv, rx).await });
        for _ in 0..100 {
            if pidfile.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let pid = std::fs::read_to_string(pidfile).unwrap();
        tx.send(true).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.0, "cancelled");
        for _ in 0..100 {
            let alive = std::process::Command::new("kill")
                .args(["-0", pid.trim()])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("mock generator did not terminate");
    }
}
