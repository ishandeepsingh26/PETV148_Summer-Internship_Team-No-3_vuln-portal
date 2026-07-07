"""
CVSS v3.1 Base Score calculator, implemented per the official FIRST.org
specification: https://www.first.org/cvss/v3-1/specification-document
"""

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

# PR weights depend on Scope (changed vs unchanged)
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

METRIC_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}


def roundup(value):
    """CVSS-specified round-up to 1 decimal place."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10


def calculate_cvss(av, ac, pr, ui, s, c, i, a):
    """
    Returns (base_score: float, severity: str, vector_string: str)
    Inputs are CVSS v3.1 base metric letter codes.
    """
    iss = 1 - ((1 - CIA_WEIGHTS[c]) * (1 - CIA_WEIGHTS[i]) * (1 - CIA_WEIGHTS[a]))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    pr_weight = PR_WEIGHTS[s][pr]
    exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * pr_weight * UI_WEIGHTS[ui]

    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = roundup(min(impact + exploitability, 10))
    else:
        base_score = roundup(min(1.08 * (impact + exploitability), 10))

    severity = severity_label(base_score)
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return base_score, severity, vector


def severity_label(score):
    if score is None:
        return "None"
    score = float(score)
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def severity_color(label):
    return {
        "None": "secondary",
        "Low": "success",
        "Medium": "warning",
        "High": "danger",
        "Critical": "dark",
    }.get(label, "secondary")
