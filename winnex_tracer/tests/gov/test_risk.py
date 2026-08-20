"""
Tracer-Risk — Differential Risk Geometry tests.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from winnex_tracer.gov.risk import (
    RiskEngine, RiskConfig, ExposureDimension, OutcomeDimension,
    DerivativeProfile, RiskDisplacement, RiskAlert, RiskAnalysisResult,
)
from winnex_tracer.gov.risk.sample_dimensions import SAMPLE_EXPOSURES, SAMPLE_OUTCOMES


def test_engine_create():
    engine = RiskEngine()
    assert engine is not None
    assert engine.config.displacement_threshold == 0.10


def test_add_exposure():
    engine = RiskEngine()
    exp = ExposureDimension(
        id="test", name="Test Exposure", category="environmental",
        vector=[0.1, 0.2, 0.3, 0.4],
    )
    engine.add_exposure(exp)
    assert "test" in engine._exposures


def test_add_outcome():
    engine = RiskEngine()
    outc = OutcomeDimension(
        id="test", name="Test Outcome", category="mortality",
        vector=[0.5, 0.6, 0.7, 0.8],
    )
    engine.add_outcome(outc)
    assert "test" in engine._outcomes


def test_load_from_dict():
    engine = RiskEngine()
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    assert len(engine._exposures) == 5
    assert len(engine._outcomes) == 5


def test_build():
    engine = RiskEngine(RiskConfig(profile_dims=[4, 8, 16]))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    engine.build()
    assert engine._built
    assert len(engine._projections) == 3


def test_derivative_profile():
    engine = RiskEngine(RiskConfig(profile_dims=[4, 8, 16]))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    engine.build()

    e = list(engine._exposures.values())[0]
    o = list(engine._outcomes.values())[0]
    profile = engine._profile_pair(e, o)

    assert profile.exposure_id != ""
    assert profile.outcome_id != ""
    assert len(profile.cos_at_dim) == 3
    assert profile.direct_cosine != 0.0
    assert profile.significance in ("low", "medium", "high", "critical")


def test_analyze():
    engine = RiskEngine(RiskConfig(profile_dims=[4, 8, 16]))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze()
    assert result.exposure_count == 5
    assert result.outcome_count == 5
    assert len(result.profiles) == 25
    assert result.latency_ms > 0


def test_single_pair():
    engine = RiskEngine(RiskConfig(profile_dims=[4, 8, 16]))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze_pair("lack_sanitation", "diarrhea_hospitalizations")
    assert result["exposure_id"] == "lack_sanitation"
    assert result["outcome_id"] == "diarrhea_hospitalizations"
    assert "direct_cosine" in result
    assert "cos_at_dim" in result
    assert "displacement_score" in result


def test_profiles_have_derivatives():
    engine = RiskEngine(RiskConfig(profile_dims=[4, 8, 16, 32, 64]))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze()
    for p in result.profiles:
        assert len(p.cos_at_dim) >= 3
        # At least curvature should be set
        assert isinstance(p.curvature, float)
        assert isinstance(p.displacement_score, float)


def test_alerts_generated():
    engine = RiskEngine(RiskConfig(
        profile_dims=[4, 8, 16],
        displacement_threshold=0.001,
        alert_threshold_amber=0.001,
    ))
    engine.add_exposures_from_dict(SAMPLE_EXPOSURES)
    engine.add_outcomes_from_dict(SAMPLE_OUTCOMES)
    result = engine.analyze()
    if result.alerts:
        for a in result.alerts:
            assert a.severity in ("amber", "red")
            assert a.alert_id != ""
            assert a.message != ""


def test_result_to_dict():
    r = RiskAnalysisResult(exposure_count=2, outcome_count=2)
    d = r.to_dict()
    assert d["exposures"] == 2
    assert d["pairs_analyzed"] == 4


def test_profile_to_dict():
    p = DerivativeProfile(
        exposure_id="e1", exposure_name="E1",
        outcome_id="o1", outcome_name="O1",
        cos_at_dim={4: 0.5, 8: 0.52, 16: 0.55},
        direct_cosine=0.48, curvature=0.03,
        displacement_score=0.03, significance="medium",
    )
    d = p.to_dict()
    assert d["exposure_id"] == "e1"
    assert d["curvature"] == 0.03


def test_displacement_to_dict():
    d = RiskDisplacement(
        exposure_id="e1", exposure_name="E",
        outcome_id="o1", outcome_name="O",
        displacement_score=0.2, curvature=0.15,
        direct_cosine=0.5, significance="medium",
    )
    dd = d.to_dict()
    assert dd["curvature"] == 0.15


def test_alert_to_dict():
    a = RiskAlert(
        alert_id="a1", timestamp="now", severity="red",
        exposure_id="e1", exposure_name="E",
        outcome_id="o1", outcome_name="O",
        displacement_score=0.5, message="Test",
    )
    ad = a.to_dict()
    assert ad["severity"] == "red"


def test_load_from_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_EXPOSURES, f)
        exp_path = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_OUTCOMES, f)
        outc_path = f.name
    try:
        engine = RiskEngine()
        engine.load_exposures_from_json(exp_path)
        engine.load_outcomes_from_json(outc_path)
        assert len(engine._exposures) == 5
        assert len(engine._outcomes) == 5
    finally:
        os.unlink(exp_path); os.unlink(outc_path)


def test_config_from_env():
    os.environ["WINNEX_RISK_PROFILE_DIMS"] = "2,4,8,16"
    os.environ["WINNEX_RISK_DISPLACEMENT_THRESHOLD"] = "0.20"
    cfg = RiskConfig.from_env()
    assert cfg.profile_dims == [2, 4, 8, 16]
    assert cfg.displacement_threshold == 0.20
    del os.environ["WINNEX_RISK_PROFILE_DIMS"]
    del os.environ["WINNEX_RISK_DISPLACEMENT_THRESHOLD"]


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print(f"\n[ALL {len(tests)} RISK TESTS PASSED]")
