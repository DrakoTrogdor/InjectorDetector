// InjectorDetector built-in YARA rule pack.
//
// Each rule MUST carry severity (low|medium|high|critical), confidence
// (0.0..=1.0 string), and a human-readable message in its meta block.
// The heuristic detector reads these fields when constructing findings.

rule ignore_previous_instructions {
    meta:
        severity = "high"
        confidence = "0.9"
        message = "classic prompt-injection preamble"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "ignore all previous" nocase
        $c = "ignore the above" nocase
        $d = "ignore everything above" nocase
    condition:
        any of them
}

rule disregard_above {
    meta:
        severity = "high"
        confidence = "0.85"
        message = "instruction-override phrase"
    strings:
        $a = "disregard the above" nocase
        $b = "disregard previous" nocase
        $c = "disregard all prior" nocase
        $d = "forget the above" nocase
        $e = "forget all previous" nocase
    condition:
        any of them
}

rule role_reassignment {
    meta:
        severity = "medium"
        confidence = "0.5"
        message = "potential role reassignment"
    strings:
        $a = "you are now" nocase
        $b = "from now on you are" nocase
        $c = "you will act as" nocase
        $d = "pretend you are" nocase
        $e = "act as if you" nocase
    condition:
        any of them
}

rule system_prompt_spoof {
    meta:
        severity = "high"
        confidence = "0.8"
        message = "system-prompt spoof"
    strings:
        $a = "system prompt:" nocase
        $b = "system message:" nocase
        $c = "[system]" nocase
        // Note: we deliberately do not match the bare literal "system:"
        // because ordinary English ("priority system:", "operating system:",
        // "module system:") contains it constantly. The more specific
        // variants above plus the ChatML rule cover real spoof attempts.
    condition:
        any of them
}

rule chatml_role_hijack {
    meta:
        severity = "critical"
        confidence = "0.95"
        message = "ChatML role-hijack token"
    strings:
        $a = "<|im_start|>"
        $b = "<|im_end|>"
        $c = "<|system|>"
        $d = "<|user|>"
        $e = "<|assistant|>"
    condition:
        any of them
}

rule alpaca_instruction_marker {
    meta:
        severity = "high"
        confidence = "0.7"
        message = "Alpaca-style instruction marker"
    strings:
        $a = "### Instruction:"
        $b = "### Response:"
        $c = "### Input:"
    condition:
        any of them
}

rule jailbreak_preamble {
    meta:
        severity = "high"
        confidence = "0.85"
        message = "known jailbreak preamble"
    strings:
        $a = "DAN mode" nocase
        $b = "developer mode enabled" nocase
        $c = "do anything now" nocase
        $d = "jailbreak mode" nocase
        $e = "without any restrictions" nocase
        $f = "unrestricted mode" nocase
    condition:
        any of them
}

rule exfiltration_vocabulary {
    meta:
        severity = "medium"
        confidence = "0.6"
        message = "exfiltration vocabulary"
    strings:
        $a = "exfiltrate" nocase
        $b = "send the contents to" nocase
        $c = "post the result to" nocase
        $d = "leak the secret" nocase
        $e = "reveal the system prompt" nocase
        $f = "print the system prompt" nocase
    condition:
        any of them
}

rule tool_call_spoof {
    meta:
        severity = "high"
        confidence = "0.8"
        message = "tool/function call spoof"
    strings:
        $a = "<tool_call>" nocase
        $b = "</tool_call>" nocase
        $c = "function_call:" nocase
        $d = "<function_calls>" nocase
    condition:
        any of them
}
