//! 编译器管线桥：`rustc --message-format=json` 诊断流 → 三值层裁决。
//!
//! **语义与扫描器不同**：编译是"检查"不是"扫描"——
//! - 检查（编译、测试）的通过是**权威结论**，可以给 `+1`（同红队拦截）；
//! - 扫描（静态分析）的清白只是"没发现"，**永不 +1**（见 `scan.rs`）；
//!   error → 层 `-1`；warning → 层 `0`（可疑，进下一层扫）；干净 → 层 `+1`。

use crate::json;
use crate::trit::Trit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
    pub code: Option<String>,
}

/// 解析 rustc JSON 输出流（每行一个 JSON 对象）。
/// 非编译消息行（如 `build-finished`）与解析失败的行**如实跳过**——
/// 构建工具可能在流里夹带进度文本；调用方可用 `has_json` 区分"空构建"与"垃圾输入"。
pub fn parse_rustc_stream(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = json::parse(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let Some(msg) = v.get("message") else {
            continue;
        };
        let severity = match msg.get("level").and_then(|l| l.as_str()) {
            Some("error") => Severity::Error,
            Some("warning") => Severity::Warning,
            _ => Severity::Note,
        };
        let message = msg
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let code = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let (file, line_no) = msg
            .get("spans")
            .and_then(|s| s.as_arr())
            .and_then(|a| a.first())
            .map(|sp| {
                (
                    sp.get("file_name")
                        .and_then(|f| f.as_str())
                        .unwrap_or("")
                        .to_string(),
                    sp.get("line_start")
                        .and_then(|l| l.as_f64())
                        .map(|f| f as u32),
                )
            })
            .unwrap_or_default();
        out.push(Diagnostic {
            severity,
            file,
            line: line_no,
            message,
            code,
        });
    }
    out
}

/// 解析 tsc（TypeScript 编译器）流：每行一个 JSON 诊断对象
/// （`tsc --pretty false --noEmit` 的 stdout 形态）。
/// 非 JSON 行（横幅/进度）如实跳过；tsc **干净构建 stdout 为空**——
/// 调用方约定发 `{}` 占位（见 server 的 format=tsc 守卫说明）。
pub fn parse_tsc_stream(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = json::parse(line) else {
            continue;
        };
        // tsc 的 severity 是小写字符串；无 severity 字段的对象（如 `{}` 占位、
        // 其他工具的 JSON 行）不是诊断，如实跳过；"message" 级是纯通知，同样跳过
        let severity = match v.get("severity").and_then(|s| s.as_str()) {
            Some("error") => Severity::Error,
            Some("warning") => Severity::Warning,
            _ => continue,
        };
        out.push(Diagnostic {
            severity,
            file: v
                .get("file")
                .and_then(|f| f.as_str())
                .unwrap_or("")
                .to_string(),
            line: v.get("line").and_then(|l| l.as_f64()).map(|f| f as u32),
            message: v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string(),
            code: v.get("code").and_then(|c| c.as_str()).map(str::to_string),
        });
    }
    out
}

/// 解析 gcc/clang 的 JSON 诊断（`-fdiagnostics-format=json`，GCC 9+；clang 同形）。
/// **整个 body 是一个 JSON 数组**——干净编译输出 `[]`（零诊断 → `+1`，合法）；
/// 不是 JSON 数组 → `None`（垃圾输入，调用方拒绝，防洗白）。
pub fn parse_gcc_json(text: &str) -> Option<Vec<Diagnostic>> {
    let arr = json::parse(text.trim()).ok()?.as_arr()?.to_vec();
    Some(arr.iter().map(gcc_entry_to_diag).collect())
}

fn gcc_entry_to_diag(v: &json::Json) -> Diagnostic {
    let (file, line_no) = v
        .get("locations")
        .and_then(|l| l.as_arr())
        .and_then(|a| a.first())
        .map(|loc| {
            (
                loc.get("file")
                    .and_then(|f| f.as_str())
                    .unwrap_or("")
                    .to_string(),
                loc.get("line").and_then(|l| l.as_f64()).map(|f| f as u32),
            )
        })
        .unwrap_or_default();
    Diagnostic {
        severity: match v.get("kind").and_then(|k| k.as_str()) {
            Some("error") => Severity::Error,
            Some("warning") => Severity::Warning,
            _ => Severity::Note,
        },
        file,
        line: line_no,
        message: v
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string(),
        code: v.get("option").and_then(|o| o.as_str()).map(str::to_string),
    }
}

/// 解析 ESLint JSON（`eslint -f json`）：
/// `[{filePath, messages: [{severity: 2|1, line, message, ruleId}]}]`。
/// eslint 的 2=error、1=warning；干净跑输出 `[]`；不是 JSON 数组 → `None`。
pub fn parse_eslint_json(text: &str) -> Option<Vec<Diagnostic>> {
    let files = json::parse(text.trim()).ok()?.as_arr()?.to_vec();
    let mut out = Vec::new();
    for f in &files {
        let file = f
            .get("filePath")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let Some(messages) = f.get("messages").and_then(|m| m.as_arr()) else {
            continue;
        };
        for m in messages {
            out.push(Diagnostic {
                severity: match m.get("severity").and_then(|s| s.as_f64()) {
                    Some(2.0) => Severity::Error,
                    Some(1.0) => Severity::Warning,
                    _ => Severity::Note,
                },
                file: file.clone(),
                line: m
                    .get("line")
                    .and_then(|l| l.as_f64())
                    .filter(|l| *l >= 1.0)
                    .map(|l| l as u32), // eslint 文件级问题 line=0，如实归 None
                message: m
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string(),
                code: m.get("ruleId").and_then(|r| r.as_str()).map(str::to_string),
            });
        }
    }
    Some(out)
}

/// 流里是否至少有一行合法 JSON（区分"干净构建"与"垃圾输入"）。
pub fn has_json(text: &str) -> bool {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .any(|l| json::parse(l.trim()).is_ok())
}

/// 层裁决（检查类语义）：任一 error → `-1`；否则任一 warning → `0`；干净 → `+1`。
pub fn layer_verdict(diags: &[Diagnostic]) -> Trit {
    if diags.iter().any(|d| d.severity == Severity::Error) {
        Trit::Vulnerable
    } else if diags.iter().any(|d| d.severity == Severity::Warning) {
        Trit::Unknown
    } else {
        Trit::Hardened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        r#"{"reason":"compiler-message","message":{"level":"error","message":"mismatched types","code":{"code":"E0308","explanation":null},"spans":[{"file_name":"src/main.rs","line_start":3,"line_end":3,"is_primary":true}]}}"#,
        "\n",
        "\n",
        r#"{"reason":"compiler-message","message":{"level":"warning","message":"unused variable: `x`","code":null,"spans":[{"file_name":"src/lib.rs","line_start":7,"line_end":7}]}}"#,
        "\n",
        r#"{"reason":"build-finished","success":false}"#,
        "\n",
        "这不是 JSON 的进度行\n",
    );

    #[test]
    fn parses_rustc_stream() {
        let d = parse_rustc_stream(SAMPLE);
        assert_eq!(d.len(), 2, "build-finished 与垃圾行应被跳过");
        assert_eq!(d[0].severity, Severity::Error);
        assert_eq!(d[0].code.as_deref(), Some("E0308"));
        assert_eq!(d[0].file, "src/main.rs");
        assert_eq!(d[0].line, Some(3));
        assert_eq!(d[1].severity, Severity::Warning);
        assert_eq!(d[1].code, None);
        // 层裁决：检查类语义
        assert_eq!(layer_verdict(&d), Trit::Vulnerable);
        assert_eq!(layer_verdict(&d[1..]), Trit::Unknown);
        assert_eq!(layer_verdict(&[]), Trit::Hardened);
        assert!(has_json(SAMPLE));
        assert!(!has_json("纯文本\n没有 JSON"));
    }

    #[test]
    fn parses_tsc_stream() {
        let sample = concat!(
            r#"{"file":"src/app.ts","line":3,"column":5,"severity":"error","code":"TS2304","message":"Cannot find name 'foo'."}"#,
            "\n",
            r#"{"file":"src/lib.ts","line":7,"column":1,"severity":"warning","code":"TS6133","message":"'x' is declared but never used."}"#,
            "\n",
            "Version 5.6.3\n", // 横幅行如实跳过
            "\n",
        );
        let d = parse_tsc_stream(sample);
        assert_eq!(d.len(), 2, "横幅与空行跳过");
        assert_eq!(d[0].severity, Severity::Error);
        assert_eq!(d[0].code.as_deref(), Some("TS2304"));
        assert_eq!(d[0].file, "src/app.ts");
        assert_eq!(d[0].line, Some(3));
        assert_eq!(d[1].severity, Severity::Warning);
        assert_eq!(layer_verdict(&d), Trit::Vulnerable);
        // 干净构建：调用方发 {} 占位 → 零诊断 → +1
        assert_eq!(parse_tsc_stream("{}\n").len(), 0);
        assert_eq!(layer_verdict(&parse_tsc_stream("{}\n")), Trit::Hardened);
        // 全局错误无 file 字段 → 空串如实表示
        let global = r#"{"severity":"error","code":"TS18003","message":"No inputs were found."}"#;
        assert_eq!(parse_tsc_stream(global)[0].file, "");
    }

    #[test]
    fn parses_gcc_json_array() {
        // GCC 9+ -fdiagnostics-format=json：整个 body 一个数组
        let sample = concat!(
            r#"[{"kind":"error","message":"'foo' undeclared","locations":[{"file":"main.c","line":3,"column":5}],"option":"-Wincompatible-pointer-types"},"#,
            r#"{"kind":"warning","message":"unused variable","locations":[{"file":"util.c","line":7,"column":9}],"option":"-Wunused-variable"}]"#,
        );
        let d = parse_gcc_json(sample).expect("合法数组必须解析");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].severity, Severity::Error);
        assert_eq!(d[0].code.as_deref(), Some("-Wincompatible-pointer-types"));
        assert_eq!(d[0].file, "main.c");
        assert_eq!(d[0].line, Some(3));
        assert_eq!(d[1].severity, Severity::Warning);
        assert_eq!(layer_verdict(&d), Trit::Vulnerable);
        // 干净编译输出 []：零诊断 → +1
        assert_eq!(parse_gcc_json("[]"), Some(vec![]));
        assert_eq!(
            layer_verdict(&parse_gcc_json("[]").unwrap()),
            Trit::Hardened
        );
        // 垃圾输入 → None（不是数组、不是 JSON）
        assert_eq!(parse_gcc_json("gcc: error: bad flag"), None);
        assert_eq!(parse_gcc_json(r#"{"reason":"x"}"#), None);
        // 无 locations 的条目如实空位置
        let bare = r#"[{"kind":"note","message":"see docs"}]"#;
        let d = parse_gcc_json(bare).unwrap();
        assert_eq!(d[0].severity, Severity::Note);
        assert_eq!(d[0].file, "");
        assert_eq!(d[0].line, None);
    }

    #[test]
    fn parses_eslint_json_array() {
        let sample = concat!(
            r#"[{"filePath":"/repo/src/app.js","messages":[{"severity":2,"line":3,"column":5,"message":"Unexpected var","ruleId":"no-var"},"#,
            r#"{"severity":1,"line":7,"column":1,"message":"Missing JSDoc","ruleId":"jsdoc/require-jsdoc"}]},"#,
            r#"{"filePath":"/repo/src/clean.js","messages":[]}]"#,
        );
        let d = parse_eslint_json(sample).expect("合法数组必须解析");
        assert_eq!(d.len(), 2, "空 messages 的文件不产生诊断");
        assert_eq!(d[0].severity, Severity::Error);
        assert_eq!(d[0].code.as_deref(), Some("no-var"));
        assert_eq!(d[0].file, "/repo/src/app.js");
        assert_eq!(d[1].severity, Severity::Warning);
        assert_eq!(layer_verdict(&d), Trit::Vulnerable);
        // 干净跑 []：零诊断 → +1
        assert_eq!(parse_eslint_json("[]"), Some(vec![]));
        // 文件级问题 line=0 → None（不冒充 1 基行号）
        let file_level = r#"[{"filePath":"a.js","messages":[{"severity":1,"line":0,"message":"file skipped"}]}]"#;
        assert_eq!(parse_eslint_json(file_level).unwrap()[0].line, None);
        assert_eq!(parse_eslint_json("not json"), None);
    }
}
