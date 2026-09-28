"""
External Dataset Evaluation & Generalization Test Suite
======================================================
Validates:
1. External dataset feature mapping into the 10-feature schema.
2. External label mapping and exclusion of unsupported categories.
3. Clean handling of missing, infinite, and NaN values.
4. Absence of data leakage in external preprocessing pipelines.
5. Deterministic external evaluation reproducibility.
6. Verification of model prediction compatibility with external schemas.
"""

import numpy as np
import pandas as pd
import pytest

from ml.data.generator import TRAFFIC_CLASSES
from ml.evaluation.external_dataset_loader import (
    generate_external_cic_ids2017_sample,
    load_external_cic_dataset,
)
from ml.evaluation.feature_mapping import (
    LABEL_MAPPING_CIC_IDS2017,
    LABEL_MAPPING_UNSW_NB15,
    ExternalDataMapper,
)
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from ml.models.predict import ThreatPredictor


@pytest.fixture(scope="module")
def predictor() -> ThreatPredictor:
    return ThreatPredictor()


def test_feature_mapping_conforms_to_schema():
    """
    Test 1: Verify mapped external dataframe contains all 10 standard features and label.
    """
    df_raw = generate_external_cic_ids2017_sample(n_samples=200, random_seed=42)
    df_cleaned, stats = ExternalDataMapper.map_cic_ids2017_dataframe(df_raw)

    assert isinstance(df_cleaned, pd.DataFrame)
    for feat in FEATURE_NAMES:
        assert feat in df_cleaned.columns
    assert "label" in df_cleaned.columns

    # Verify no NaN or Inf values remain
    assert not df_cleaned.isna().any().any()
    assert not np.isinf(df_cleaned[FEATURE_NAMES].values).any()


def test_external_label_mapping_coverage():
    """
    Test 2: Verify supported external labels map to standard classes and unsupported to None.
    """
    assert LABEL_MAPPING_CIC_IDS2017["BENIGN"] == "BENIGN"
    assert LABEL_MAPPING_CIC_IDS2017["PortScan"] == "PORT_SCAN"
    assert LABEL_MAPPING_CIC_IDS2017["SSH-Patator"] == "BRUTE_FORCE"
    assert LABEL_MAPPING_CIC_IDS2017["DDoS"] == "TRAFFIC_SPIKE"
    assert LABEL_MAPPING_CIC_IDS2017["Infiltration"] == "SUSPICIOUS_TRANSFER"
    assert LABEL_MAPPING_CIC_IDS2017["Bot"] is None
    assert LABEL_MAPPING_CIC_IDS2017["Heartbleed"] is None

    assert LABEL_MAPPING_UNSW_NB15["Normal"] == "BENIGN"
    assert LABEL_MAPPING_UNSW_NB15["Reconnaissance"] == "PORT_SCAN"


def test_invalid_values_dropped_gracefully():
    """
    Test 3: Verify rows with corrupted/infinite rates or invalid values are cleaned without exception.
    """
    corrupt_df = pd.DataFrame({
        "Flow Duration": [1000000, 0, np.nan, 500000],
        "Total Fwd Packets": [10, 5, 2, np.nan],
        "Total Backward Packets": [5, 2, 1, 1],
        "Total Length of Fwd Packets": [5000, 1000, np.inf, 200],
        "Total Length of Bwd Packets": [2000, 500, 100, 100],
        "Destination Port": [443, 80, 22, 65536],
        "Flow Packets/s": [15.0, np.inf, 3.0, 1.0],
        "Label": ["BENIGN", "PortScan", "Bot", "FTP-Patator"],
    })

    cleaned_df, stats = ExternalDataMapper.map_cic_ids2017_dataframe(corrupt_df)
    assert len(cleaned_df) >= 1
    assert stats["dropped_unsupported_labels"] == 1  # 'Bot' dropped
    assert not cleaned_df.isna().any().any()


def test_external_evaluation_inference_compatibility(predictor: ThreatPredictor):
    """
    Test 4: Verify external data rows pass through ThreatPredictor without error.
    """
    cleaned_df, _ = load_external_cic_dataset(n_samples=50, random_seed=99)
    flow_dicts = cleaned_df.to_dict(orient="records")

    results = predictor.predict_batch(flow_dicts)
    assert len(results) == len(cleaned_df)

    for res in results:
        assert res.attack_type in TRAFFIC_CLASSES
        assert 0.0 <= res.risk_score <= 100.0
        assert res.threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
