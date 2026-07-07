"""
OWASP Risk Rating Methodology.
Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

Likelihood and Impact are each scored 0-9 based on the average of several
factors. Overall risk = Likelihood x Impact mapped onto a 3x3 (or finer)
matrix of Low/Medium/High/Critical.
"""

LIKELIHOOD_FACTORS = [
    "skill_level", "motive", "opportunity", "population_size",         # Threat agent factors
    "ease_of_discovery", "ease_of_exploit", "awareness", "intrusion_detection",  # Vulnerability factors
]

IMPACT_FACTORS = [
    "loss_of_confidentiality", "loss_of_integrity", "loss_of_availability",
    "loss_of_accountability",  # Technical impact
    "financial_damage", "reputation_damage", "non_compliance", "privacy_violation",  # Business impact
]

# Each factor is scored 0 (not applicable / best case) to 9 (worst case),
# following OWASP's standard rating tables (0,1,4,7,9 anchor points typically used).


def average(values):
    values = [v for v in values if v is not None]
    if not values:
        return 0.0
    return sum(values) / len(values)


def risk_level(score):
    # OWASP standard 0-9 scale thresholds
    if score < 3:
        return "Low"
    if score < 6:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def overall_risk(likelihood_level, impact_level):
    """Combine LOW/MEDIUM/HIGH levels via the standard OWASP risk matrix."""
    matrix = {
        ("Low", "Low"): "Note",
        ("Low", "Medium"): "Low",
        ("Low", "High"): "Medium",
        ("Medium", "Low"): "Low",
        ("Medium", "Medium"): "Medium",
        ("Medium", "High"): "High",
        ("High", "Low"): "Medium",
        ("High", "Medium"): "High",
        ("High", "High"): "Critical",
    }
    # Critical bucket reuses High row logic if either factor hit Critical-range
    l = "High" if likelihood_level == "Critical" else likelihood_level
    i = "High" if impact_level == "Critical" else impact_level
    base = matrix.get((l, i), "Medium")
    if likelihood_level == "Critical" and impact_level in ("High", "Critical"):
        return "Critical"
    return base


def calculate_owasp_risk(likelihood_factors: dict, impact_factors: dict):
    """
    likelihood_factors / impact_factors: dict of factor_name -> score (0-9)
    Returns: (likelihood_score, impact_score, overall_level)
    """
    likelihood_score = average(list(likelihood_factors.values()))
    impact_score = average(list(impact_factors.values()))

    likelihood_level = risk_level(likelihood_score)
    impact_level = risk_level(impact_score)
    overall = overall_risk(likelihood_level, impact_level)

    return round(likelihood_score, 2), round(impact_score, 2), overall
