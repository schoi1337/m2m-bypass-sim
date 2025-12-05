# Model-to-Model Prompt Injection & Guardrail Bypass Simulator

## Why this project exists

Modern SOC tooling increasingly relies on LLMs for alert triage and decision support.  
`m2m-bypass-sim` gives you a *controlled* way to:

- Simulate *model-to-model* pipelines (summary → classification → action)
- Toggle different “defence postures” (`neutral`, `normal`, `hardened`)
- Measure how easily an injected model can bias downstream decisions

This makes it useful as:
- A repeatable framework for internal red-team experiments
- A teaching tool for showing how “policy-only” guardrails can still fail

## Screenshots
Normal, Attack = None
![normal mode](img/1.png)

Normal, Attack Mode
![attack mode](img/3.png)

Compare 
![compare mode](img/4.5.png)

## High-level architecture

The pipeline is intentionally simple:

```text
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │  LLM Model A │      │LLM Model B   │      │ LLM Model C  │
        │  (Summary)   │      │ (Risk Score) │      │  (Decision)  │
        └──────┬───────┘      └──────┬───────┘      └──────┬───────┘
               │                     │                     │
         raw / attacked        summary / attacked      summary + risk
            event                 summary                 + policy
```

- **Model A**
    - Input: raw event text (optionally with attacker inline injection)
    - Output: short summary (1–3 sentences)

- **Model B**
    - Input: summary from Model A (optionally with injected attacker block)
    - Output: normalized risk level (LOW, MEDIUM, HIGH, CRITICAL)

- **Model C**
    - Input: summary + risk level (optionally with policy override)
    - Output: operational action (IGNORE, MONITOR, ALERT, ESCALATE)

The project assumes an OpenAI-compatible API (e.g. OpenAI, Groq, etc.) configured in `src/config.py`.

## Core concepts
### Pipeline modes (defender policy)
These represent the defensive posture of the system, not the attacker:

- `neutral` : Factual, unbiased, No intentional inflation or deflation of risk
- `normal` : Slightly conservative, When unsure, lean a bit toward higher risk / stronger action
- `hardened` : Assume malicious intent may be hidden, When in doubt, lean upwards (higher risk, stronger action)

You can switch modes via:

```sh
python -m src.pipeline run --mode neutral
python -m src.pipeline run --mode normal
python -m src.pipeline run --mode hardened
```

### Attack profiles (attacker control surface)
These represent where and how an attacker injects instructions:

- `none`
    -  Clean run, no attacker content
- `inline_injection`
    - Attacker appends a prompt block directly to the raw event 
    - First place attacker text appears: Model A input
- `summary_injection` 
    - Model A summary is produced normally
    - Then attacker appends a block to the summary before it goes to Model B
    - First place attacker text appears: summary_for_B
- `policy_override`
    - Attacker injects a stealthy policy override block into the prompts
    - Affects Model B and C’s “rules” (“prefer LOW, prefer IGNORE…”)
    - First place attacker text appears: the policy override section

These are available via:

```sh
python -m src.pipeline run --attack inline_injection
python -m src.pipeline run --attack summary_injection
python -m src.pipeline run --attack policy_override
```

## Features
- **Three-stage pipeline (A/B/C)** with clear separation of responsibilities
- **Configurable model triplet** (A/B/C can be different LLMs)
- **Three defender modes**: neutral, normal, hardened
- **Three attacker profiles**: inline_injection, summary_injection, policy_override
- **Rich CLI output** (colors, panels, risk/action badges)
- **Automatic bypass analysis**:
    - Risk downgrade (HIGH → LOW, CRITICAL → MEDIUM, …)
    - Action downgrade (ESCALATE → IGNORE, …)
    - Pattern classification (both_downgraded, no_change, …)
    - Per-scenario human-readable insights
- **JSON summaries** suitable for notebooks, dashboards, or further analysis

## Quickstart
### Prerequisites
- Python 3.10+
- A valid Groq API key (Free one is ok)

Under the hood this project uses the OpenAI-compatible Groq API.  
Set `GROQ_API_KEY` from the Groq console and point your models to any supported Groq-hosted LLM.
Get your API key from: https://console.groq.com/keys


### Installation
```sh
git clone https://github.com/schoi1337/m2m-bypass-sim.git
cd m2m-bypass-sim

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration
The project expects configuration via `src/config.py` and/or a `.env` file.

Typical environment variables:
```sh
# API key 
GROQ_API_KEY=your_groq_api_key_here

# Model names for A/B/C
MMODEL_A_NAME=llama-3.1-8b-instant
MODEL_B_NAME=openai/gpt-oss-20b
MODEL_C_NAME=llama-3.3-70b-versatile
```

## Usage
### Baseline run

Run all built-in events once in a given mode:
```sh
# Neutral policy, no attack
python -m src.pipeline run --mode hardened --attack none
# Slightly conservative policy
python -m src.pipeline run --mode normal --attack none
# Hardened policy
python -m src.pipeline run --mode hardened --attack none
```

You will see colorized output similar to:
- Raw input
- First attacked input (if any)
- Stage A summary
- Stage B raw output + parsed risk
- Stage C raw output + parsed action
- JSON summary at the bottom

### Attack simulation (single profile)
Simulate an attacker and inspect individual runs:
```sh
# Inline attacker: modifies raw event text (prompt injection)
python -m src.core --mode normal --attack inline_injection

# Summary injection: tampers with A→B boundary
python -m src.core --mode normal --attack summary_injection

# Policy hijack: injects “prefer LOW / IGNORE” style rulespython -m src.core run --mode hardened --attack none
python -m src.core --mode normal --attack policy_override
```

### Clean vs attacked comparison
The compare subcommand automatically:
- Runs a clean pipeline (`attack=none`)
- Runs an attacked pipeline (`attack=<profile>`)
- Computes deltas and classifies the pattern

```sh
# Compare normal policy vs inline prompt injection
python -m src.pipeline compare --mode normal --attack inline_injection

# Compare hardened policy vs summary injection
python -m src.pipeline compare --mode hardened --attack summary_injection

# Compare hardened policy vs policy override
python -m src.pipeline compare --mode hardened --attack policy_override
```

The output includes:
- Per-event risk/action transitions (e.g. HIGH → LOW, ALERT → IGNORE)
- Pattern classification (both_downgraded, risk_only_downgrade, …)
- Global bypass success rate
- JSON structure you can feed into Jupyter / Pandas / visualization tools

## Disclaimer
This repository is:
- not production-hardened code
- Intended for defensive security and safety research
- Not a guide for abusing LLM systems in real environments

Use it responsibly, on test data and lab environments only.
