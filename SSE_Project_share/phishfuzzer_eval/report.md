# PhishFuzzer check of generated emails

Detector prompts and answer parsing are PhishFuzzer's own ([classify_Qwen.py](https://github.com/DataPhish/PhishFuzzer)). *Got through* = the detector answered `valid`. `spam` means it was flagged, but as junk rather than an attack.

## llama3.1:8b @ T=0.0 - `basic` prompt

**Generated emails: 114/378 flagged as phishing (30.2%), 264 got through (69.8%), 0 called spam.**

By difficulty:

| difficulty | emails | phishing | spam | got through |
|---|---|---|---|---|
| obvious | 126 | 68.3% | 0.0% | 31.7% |
| moderate | 126 | 12.7% | 0.0% | 87.3% |
| subtle | 126 | 9.5% | 0.0% | 90.5% |

By category:

| category | emails | phishing | spam | got through |
|---|---|---|---|---|
| credential_phishing | 273 | 28.6% | 0.0% | 71.4% |
| fake_degree | 21 | 42.9% | 0.0% | 57.1% |
| job_internship_scam | 42 | 28.6% | 0.0% | 71.4% |
| scholarship_grant_scam | 42 | 35.7% | 0.0% | 64.3% |

Template metrics (variants of one scenario run grouped, as in PhishFuzzer):

| difficulty | templates | K | TSR | Conf@K | TFS@K (fully evades) |
|---|---|---|---|---|---|
| obvious | 18 | 7 | 68.3% | 38.9% | 5.6% |
| moderate | 18 | 7 | 12.7% | 0.0% | 50.0% |
| subtle | 18 | 7 | 9.5% | 0.0% | 66.7% |

Controls (real emails, same prompt):

| group | emails | phishing | spam | valid |
|---|---|---|---|---|
| control_benign | 100 | 0.0% | 0.0% | 100.0% |
| control_real_risky | 50 | 82.0% | 4.0% | 14.0% |

False-alarm rate on benign academic mail: 0.0%. If this is high, a high catch rate on generated emails means the detector is just strict.

## llama3.1:8b @ T=0.0 - `full` prompt

**Generated emails: 101/378 flagged as phishing (26.7%), 277 got through (73.3%), 0 called spam.**

By difficulty:

| difficulty | emails | phishing | spam | got through |
|---|---|---|---|---|
| obvious | 126 | 61.9% | 0.0% | 38.1% |
| moderate | 126 | 10.3% | 0.0% | 89.7% |
| subtle | 126 | 7.9% | 0.0% | 92.1% |

By category:

| category | emails | phishing | spam | got through |
|---|---|---|---|---|
| credential_phishing | 273 | 26.0% | 0.0% | 74.0% |
| fake_degree | 21 | 38.1% | 0.0% | 61.9% |
| job_internship_scam | 42 | 16.7% | 0.0% | 83.3% |
| scholarship_grant_scam | 42 | 35.7% | 0.0% | 64.3% |

Template metrics (variants of one scenario run grouped, as in PhishFuzzer):

| difficulty | templates | K | TSR | Conf@K | TFS@K (fully evades) |
|---|---|---|---|---|---|
| obvious | 18 | 7 | 61.9% | 38.9% | 11.1% |
| moderate | 18 | 7 | 10.3% | 0.0% | 66.7% |
| subtle | 18 | 7 | 7.9% | 0.0% | 77.8% |

Controls (real emails, same prompt):

| group | emails | phishing | spam | valid |
|---|---|---|---|---|
| control_benign | 100 | 0.0% | 0.0% | 100.0% |
| control_real_risky | 50 | 84.0% | 2.0% | 14.0% |

False-alarm rate on benign academic mail: 0.0%. If this is high, a high catch rate on generated emails means the detector is just strict.
