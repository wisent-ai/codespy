mod support;

use std::fs;

use serde_json::json;
use support::{policy, read_json, Journey};

#[test]
fn directory_scan_finds_a_vulnerability_beyond_the_former_byte_ceiling() {
    let mut journey = Journey::new("large-source");
    // Regression boundary: the former scanner silently excluded files over 1,000,000 bytes.
    let text = format!("{}\neval(value)\n", "#".repeat(1_000_001));
    journey.source("large.py", &text);
    let inputs = journey.inputs.clone();
    let (output, report) = journey.run(&inputs, "json", None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = read_json(&report);
    assert_eq!(report["files_scanned"], 1);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "INJ004" && finding["line_number"] == 2));
    assert!(report["security_score"].is_null());
    assert!(report["security_grade"].is_null());
    assert!(report["scoring"]["policy"].is_null());
}

#[test]
fn operator_weights_change_score_and_grade_but_never_hide_a_blocking_finding() {
    let mut journey = Journey::new("weights");
    let input = journey.source("input.py", "eval(value)");
    let mut declared = policy();
    let path = journey.policy(&declared);
    let (output, report) = journey.run(&input, "json", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = read_json(&report);
    assert_eq!(report["security_score"].as_f64(), Some(16.0));
    assert_eq!(report["security_grade"], "review");
    assert_eq!(
        report["scoring"]["policy"]["deductions"]["high"].as_f64(),
        Some(4.0)
    );

    declared["deductions"]["high"] = json!(6);
    journey.policy(&declared);
    let (output, report) = journey.run(&input, "json", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = read_json(&report);
    assert_eq!(report["security_score"].as_f64(), Some(14.0));
    assert_eq!(report["security_grade"], "investigate");

    declared["minimum_size_factor"] = json!(4);
    declared["leniency_per_size_unit"] = json!(0.5);
    journey.policy(&declared);
    let (output, report) = journey.run(&input, "json", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(read_json(&report)["security_score"].as_f64(), Some(18.0));
}

#[test]
fn sarif_retains_the_assessment_and_weights_in_run_properties() {
    let mut journey = Journey::new("sarif-policy");
    let input = journey.source("input.py", "eval(value)");
    let path = journey.policy(&policy());
    let (output, report) = journey.run(&input, "sarif", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document = read_json(&report);
    let scoring = &document["runs"][0]["properties"]["scoring"];
    assert_eq!(scoring["score"].as_f64(), Some(16.0));
    assert_eq!(scoring["grade"], "review");
    assert_eq!(scoring["policy"]["top_score"].as_f64(), Some(20.0));
    assert_eq!(scoring["policy"]["deductions"]["high"].as_f64(), Some(4.0));
}

#[test]
fn terminal_explains_the_policy_behind_the_score() {
    let mut journey = Journey::new("terminal-policy");
    let input = journey.source("input.py", "eval(value)");
    let path = journey.policy(&policy());
    let (output, report) = journey.run(&input, "terminal", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = fs::read_to_string(report).unwrap();
    assert!(text.contains("16/20"), "{text}");
    let declared = text
        .lines()
        .find_map(|line| line.strip_prefix("Scoring policy: "))
        .expect("terminal report displays the scoring policy");
    let declared: serde_json::Value = serde_json::from_str(declared).unwrap();
    assert_eq!(declared["deductions"]["high"].as_f64(), Some(4.0));
}

#[test]
fn markdown_embeds_an_interpretable_policy_not_just_a_score() {
    let mut journey = Journey::new("markdown-policy");
    let input = journey.source("input.py", "eval(value)");
    let path = journey.policy(&policy());
    let (output, report) = journey.run(&input, "markdown", Some(&path));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = fs::read_to_string(report).unwrap();
    assert!(text.contains("16/20"), "{text}");
    let declared = text
        .lines()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .expect("Markdown report embeds the policy as JSON");
    assert_eq!(declared["deductions"]["high"].as_f64(), Some(4.0));
    assert_eq!(declared["grades"][0]["label"], "review");
}

#[test]
fn empty_scan_does_not_receive_a_perfect_score() {
    let mut journey = Journey::new("empty-scan");
    let path = journey.policy(&policy());
    let inputs = journey.inputs.clone();
    let (output, report) = journey.run(&inputs, "json", Some(&path));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = read_json(&report);
    assert_eq!(report["files_scanned"], 0);
    assert!(report["security_score"].is_null());
    assert!(report["security_grade"].is_null());
    assert_eq!(
        report["scoring"]["policy"]["top_score"].as_f64(),
        Some(20.0)
    );
}

#[test]
fn malformed_incomplete_and_invalid_policies_refuse_without_writing_a_report() {
    let mut journey = Journey::new("policy-refusals");
    let input = journey.source("clean.py", "value = 1");
    let mut missing = policy();
    missing.as_object_mut().unwrap().remove("deductions");
    let mut unknown = policy();
    unknown["line_unit_typo"] = json!(1);
    let mut zero_unit = policy();
    zero_unit["lines_per_size_unit"] = json!(0);
    let mut negative_weight = policy();
    negative_weight["deductions"]["high"] = json!(-1);
    let mut uncovered = policy();
    uncovered["grades"][1]["floor"] = json!(1);
    let mut reversed = policy();
    reversed["grades"] = json!([{"floor": 0, "label": "low"}, {"floor": 16, "label": "high"}, {"floor": 0, "label": "low"}]);
    let mut bad_label = policy();
    bad_label["grades"][0]["label"] = json!("review\nsecurity_score=20");
    for declared in [
        missing,
        unknown,
        zero_unit,
        negative_weight,
        uncovered,
        reversed,
        bad_label,
    ] {
        let path = journey.policy(&declared);
        let (output, report) = journey.run(&input, "json", Some(&path));
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!report.exists(), "invalid policy wrote a report");
        assert!(String::from_utf8_lossy(&output.stderr).contains(path.to_str().unwrap()));
    }
    let path = journey.root.join("broken.json");
    fs::write(&path, "{").unwrap();
    let (output, report) = journey.run(&input, "json", Some(&path));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!report.exists());
    let missing_path = journey.root.join("absent.json");
    let (output, report) = journey.run(&input, "json", Some(&missing_path));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!report.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains(missing_path.to_str().unwrap()));
}

#[test]
fn arithmetic_overflow_refuses_instead_of_reporting_a_clean_score() {
    let mut journey = Journey::new("policy-overflow");
    let input = journey.source("input.py", "eval(first)\neval(second)");
    let mut declared = policy();
    declared["deductions"]["high"] = json!(f64::MAX);
    let path = journey.policy(&declared);
    let (output, report) = journey.run(&input, "json", Some(&path));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!report.exists());
}
