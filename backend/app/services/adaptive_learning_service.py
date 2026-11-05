"""
Adaptive Machine Learning Service
=================================
Manages feedback-driven continuous learning, ground-truth label curation,
reproducible training dataset preparation, isolated candidate retraining,
and controlled model evaluation without modifying active production weights.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import joblib
import numpy as np
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
import xgboost as xgb

from backend.app.config import settings
from backend.app.models.adaptive_learning import AdaptiveFlowFeedbackModel, AdaptiveTrainingRunModel
from backend.app.models.pcap_ingestion import PcapIngestionModel
from backend.app.services.ml_service import MLService
from ml.features.extractor import FEATURE_NAMES_V2

logger = logging.getLogger("adaptive_learning")

TARGET_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER",
]


class AdaptiveLearningService:

    @classmethod
    def get_telemetry(cls, db: Session) -> Dict[str, Any]:
        """
        Return comprehensive telemetry on ingestion history, feedback volume,
        class balance, and candidate training runs.
        """
        total_ingestions = db.scalar(select(func.count(PcapIngestionModel.id))) or 0
        total_flows = db.scalar(select(func.count(AdaptiveFlowFeedbackModel.id))) or 0
        
        verified_count = db.scalar(
            select(func.count(AdaptiveFlowFeedbackModel.id))
            .where(AdaptiveFlowFeedbackModel.feedback_status.in_(["CONFIRMED", "CORRECTED"]))
        ) or 0
        
        unverified_count = db.scalar(
            select(func.count(AdaptiveFlowFeedbackModel.id))
            .where(AdaptiveFlowFeedbackModel.feedback_status == "UNVERIFIED")
        ) or 0
        
        excluded_count = db.scalar(
            select(func.count(AdaptiveFlowFeedbackModel.id))
            .where(AdaptiveFlowFeedbackModel.feedback_status == "EXCLUDED")
        ) or 0

        # Verified class distribution
        class_dist_rows = db.execute(
            select(
                AdaptiveFlowFeedbackModel.verified_label,
                func.count(AdaptiveFlowFeedbackModel.id),
            )
            .where(AdaptiveFlowFeedbackModel.is_training_eligible == True)
            .group_by(AdaptiveFlowFeedbackModel.verified_label)
        ).all()
        class_distribution = {row[0]: row[1] for row in class_dist_rows if row[0]}

        # Latest training run
        latest_run = db.scalar(
            select(AdaptiveTrainingRunModel)
            .order_by(desc(AdaptiveTrainingRunModel.created_at))
            .limit(1)
        )

        return {
            "total_ingested_pcaps": total_ingestions,
            "total_extracted_flows": total_flows,
            "verified_feedback_count": verified_count,
            "unverified_flow_count": unverified_count,
            "excluded_flow_count": excluded_count,
            "verified_class_distribution": class_distribution,
            "training_threshold_min_samples": 5,
            "is_retraining_eligible": verified_count >= 5,
            "active_model_version": MLService.get_active_version(),
            "standby_model_version": MLService.get_previous_version(),
            "latest_candidate_run": latest_run.to_dict() if latest_run else None,
        }

    @classmethod
    def get_feedbacks(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 25,
        status_filter: Optional[str] = None,
        ingestion_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return paginated list of network flow records for analyst review and label curation.
        """
        stmt = select(AdaptiveFlowFeedbackModel)
        count_stmt = select(func.count(AdaptiveFlowFeedbackModel.id))

        if status_filter:
            stmt = stmt.where(AdaptiveFlowFeedbackModel.feedback_status == status_filter.upper())
            count_stmt = count_stmt.where(AdaptiveFlowFeedbackModel.feedback_status == status_filter.upper())

        if ingestion_id:
            stmt = stmt.where(AdaptiveFlowFeedbackModel.ingestion_id == ingestion_id)
            count_stmt = count_stmt.where(AdaptiveFlowFeedbackModel.ingestion_id == ingestion_id)

        total = db.scalar(count_stmt) or 0
        items = db.scalars(
            stmt.order_by(desc(AdaptiveFlowFeedbackModel.timestamp))
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "records": [r.to_dict() for r in items],
        }

    @classmethod
    def submit_feedback(
        cls,
        db: Session,
        feedback_id: str,
        action: str,  # "CONFIRM", "CORRECT", "EXCLUDE", "RESET"
        verified_label: Optional[str] = None,
        reviewer: str = "admin",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Records human analyst label verification or correction.
        """
        item = db.scalar(select(AdaptiveFlowFeedbackModel).where(AdaptiveFlowFeedbackModel.id == feedback_id))
        if not item:
            raise ValueError(f"Feedback flow record '{feedback_id}' not found.")

        act = action.upper()
        now = datetime.now(timezone.utc)

        if act == "CONFIRM":
            item.verified_label = item.predicted_class
            item.feedback_status = "CONFIRMED"
            item.is_training_eligible = True
        elif act == "CORRECT":
            if not verified_label or verified_label.upper() not in TARGET_CLASSES:
                raise ValueError(f"Invalid label '{verified_label}'. Allowed: {TARGET_CLASSES}")
            item.verified_label = verified_label.upper()
            item.feedback_status = "CORRECTED"
            item.is_training_eligible = True
        elif act == "EXCLUDE":
            item.feedback_status = "EXCLUDED"
            item.is_training_eligible = False
        elif act == "RESET":
            item.verified_label = None
            item.feedback_status = "UNVERIFIED"
            item.is_training_eligible = False
        else:
            raise ValueError(f"Unsupported action '{action}'. Use CONFIRM, CORRECT, EXCLUDE, or RESET.")

        item.reviewed_by = reviewer
        item.reviewed_at = now
        if notes:
            item.notes = notes

        db.commit()
        return item.to_dict()

    @classmethod
    def prepare_training_dataset(cls, db: Session, min_samples: int = 5) -> Dict[str, Any]:
        """
        Validates available verified feedback data and prepares clean feature matrix.
        """
        records = db.scalars(
            select(AdaptiveFlowFeedbackModel)
            .where(AdaptiveFlowFeedbackModel.is_training_eligible == True)
        ).all()

        count = len(records)
        if count < min_samples:
            return {
                "eligible": False,
                "verified_sample_count": count,
                "min_required": min_samples,
                "message": f"Insufficient verified samples ({count}/{min_samples}). Verify more flows before retraining.",
            }

        # Check for NaN / Infinity
        valid_records = []
        invalid_count = 0
        class_counts = {}

        for r in records:
            feats = r.flow_features
            has_nan_inf = False
            for k in FEATURE_NAMES_V2:
                v = float(feats.get(k, 0.0))
                if np.isnan(v) or np.isinf(v):
                    has_nan_inf = True
                    break
            if has_nan_inf:
                invalid_count += 1
            else:
                valid_records.append(r)
                lbl = r.verified_label
                class_counts[lbl] = class_counts.get(lbl, 0) + 1

        return {
            "eligible": len(valid_records) >= min_samples,
            "verified_sample_count": count,
            "valid_samples": len(valid_records),
            "invalid_nan_inf_samples": invalid_count,
            "class_distribution": class_counts,
            "features_used": FEATURE_NAMES_V2,
            "message": f"Successfully prepared {len(valid_records)} verified training samples across {len(class_counts)} classes.",
        }

    @classmethod
    def trigger_candidate_training(
        cls,
        db: Session,
        candidate_version: Optional[str] = None,
        created_by: str = "admin",
    ) -> Dict[str, Any]:
        """
        Executes isolated candidate retraining using verified human feedback combined
        with baseline benchmark records, saving artifacts to a dedicated versioned directory.
        Never modifies active production model weights.
        """
        version = candidate_version or f"adaptive_v{int(time.time())}"
        artifacts_dir = Path(__file__).resolve().parent.parent.parent.parent / "ml" / "models" / "candidates" / version
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        prep = cls.prepare_training_dataset(db, min_samples=1)
        if not prep["eligible"] and prep["valid_samples"] == 0:
            raise ValueError("No verified training samples available for candidate retraining.")

        run_id = f"run-{uuid.uuid4().hex[:8]}"
        run_model = AdaptiveTrainingRunModel(
            id=run_id,
            candidate_version=version,
            base_model_version=MLService.get_active_version(),
            status="TRAINING",
            created_at=datetime.now(timezone.utc),
            sample_count=prep["valid_samples"],
            class_distribution=prep["class_distribution"],
            artifacts_dir=str(artifacts_dir),
        )
        db.add(run_model)
        db.commit()

        start_time = time.time()
        try:
            # 1. Collect verified samples
            records = db.scalars(
                select(AdaptiveFlowFeedbackModel)
                .where(AdaptiveFlowFeedbackModel.is_training_eligible == True)
            ).all()

            X_feedback = []
            y_feedback = []
            for r in records:
                row = [float(r.flow_features.get(f, 0.0)) for f in FEATURE_NAMES_V2]
                X_feedback.append(row)
                y_feedback.append(r.verified_label)

            X_new = np.array(X_feedback, dtype=np.float64)
            y_new = np.array(y_feedback, dtype=str)

            # 2. Replay baseline reference data (prevent catastrophic forgetting)
            rng = np.random.default_rng(42)
            n_synthetic_baseline = max(200, len(X_new) * 10)
            X_base_rows = []
            y_base_rows = []
            for cls_idx, c_name in enumerate(TARGET_CLASSES):
                sub_count = n_synthetic_baseline // len(TARGET_CLASSES)
                if c_name == "BENIGN":
                    base_row = [15.0, 1200.0, 1.0, 15.0, 443.0, 1.0, 1200.0, 15.0, 80.0]
                elif c_name == "PORT_SCAN":
                    base_row = [25.0, 1100.0, 2.0, 12.5, 80.0, 25.0, 550.0, 12.5, 44.0]
                elif c_name == "BRUTE_FORCE":
                    base_row = [35.0, 8500.0, 1.8, 19.4, 22.0, 1.0, 4722.0, 19.4, 242.0]
                elif c_name == "TRAFFIC_SPIKE":
                    base_row = [5000.0, 5000000.0, 0.5, 10000.0, 80.0, 1.0, 10000000.0, 10000.0, 1000.0]
                else:
                    base_row = [500.0, 500000.0, 10.0, 50.0, 8443.0, 1.0, 50000.0, 50.0, 1000.0]
                
                noise = rng.normal(1.0, 0.08, size=(sub_count, len(FEATURE_NAMES_V2)))
                noise[:, 4] = 1.0  # keep port un-noised
                noisy_samples = np.abs(np.array(base_row) * noise)
                X_base_rows.append(noisy_samples)
                y_base_rows.extend([c_name] * sub_count)

            X_base = np.vstack(X_base_rows)
            y_base = np.array(y_base_rows, dtype=str)

            X_all = np.vstack([X_base, X_new])
            y_all = np.concatenate([y_base, y_new])

            # 3. Fit Preprocessing Scaler and Encoder
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X_all)

            le = LabelEncoder()
            le.fit(TARGET_CLASSES)
            y_encoded = le.transform(y_all)

            # 4. Train Candidate XGBoost Model
            model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="mlogloss",
                n_jobs=-1,
            )
            model.fit(X_scaled, y_encoded)

            # 5. Evaluate Candidate Model
            y_pred_enc = model.predict(X_scaled)
            y_pred_str = le.inverse_transform(y_pred_enc)

            acc = float(accuracy_score(y_all, y_pred_str))
            macro_f1 = float(f1_score(y_all, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
            weighted_f1 = float(f1_score(y_all, y_pred_str, labels=TARGET_CLASSES, average="weighted", zero_division=0))
            
            cm = confusion_matrix(y_all, y_pred_str, labels=TARGET_CLASSES)
            benign_idx = TARGET_CLASSES.index("BENIGN")
            benign_total = cm[benign_idx, :].sum()
            benign_fp = cm[benign_idx, :].sum() - cm[benign_idx, benign_idx]
            fpr = float(benign_fp / benign_total) if benign_total > 0 else 0.0
            
            attack_total = cm.sum() - benign_total
            attack_fn = cm[:, benign_idx].sum() - cm[benign_idx, benign_idx]
            fnr = float(attack_fn / attack_total) if attack_total > 0 else 0.0

            metrics = {
                "accuracy": round(acc, 4),
                "macro_f1": round(macro_f1, 4),
                "weighted_f1": round(weighted_f1, 4),
                "false_positive_rate": round(fpr, 4),
                "false_negative_rate": round(fnr, 4),
                "training_duration_seconds": round(time.time() - start_time, 2),
                "total_training_samples": len(X_all),
                "verified_feedback_samples_used": len(X_new),
            }

            # 6. Save Artifacts to isolated directory
            joblib.dump(model, artifacts_dir / "model.joblib")
            joblib.dump(scaler, artifacts_dir / "scaler.joblib")
            joblib.dump(le, artifacts_dir / "label_encoder.joblib")

            meta = {
                "candidate_version": version,
                "base_version": run_model.base_model_version,
                "algorithm": "XGBClassifier",
                "feature_schema": FEATURE_NAMES_V2,
                "feature_count": 9,
                "classes": TARGET_CLASSES,
                "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "created_by": created_by,
                "metrics": metrics,
            }
            with open(artifacts_dir / "metadata.json", "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            with open(artifacts_dir / "feature_schema.json", "w", encoding="utf-8") as f:
                json.dump({"version": version, "feature_names": FEATURE_NAMES_V2, "count": 9}, f, indent=2)

            # 7. Update Database Run Record
            run_model.status = "COMPLETED"
            run_model.completed_at = datetime.now(timezone.utc)
            run_model.training_metrics = metrics
            run_model.evaluation_comparison = {
                "active_model_version": MLService.get_active_version(),
                "candidate_accuracy": metrics["accuracy"],
                "candidate_macro_f1": metrics["macro_f1"],
                "candidate_fpr": metrics["false_positive_rate"],
                "candidate_fnr": metrics["false_negative_rate"],
                "acceptance_ready": acc >= 0.95 and macro_f1 >= 0.90 and fpr <= 0.02,
            }
            db.commit()

            return run_model.to_dict()

        except Exception as e:
            db.rollback()
            run_model.status = "FAILED"
            run_model.error_message = str(e)
            run_model.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise RuntimeError(f"Candidate training failed: {e}")

    @classmethod
    def list_runs(cls, db: Session, limit: int = 20) -> List[Dict[str, Any]]:
        runs = db.scalars(
            select(AdaptiveTrainingRunModel)
            .order_by(desc(AdaptiveTrainingRunModel.created_at))
            .limit(limit)
        ).all()
        return [r.to_dict() for r in runs]

    @classmethod
    def approve_candidate_promotion(
        cls,
        db: Session,
        run_id: str,
        approved_by: str = "admin",
    ) -> Dict[str, Any]:
        """
        Promotes an evaluated candidate model after explicit administrator confirmation.
        """
        run = db.scalar(select(AdaptiveTrainingRunModel).where(AdaptiveTrainingRunModel.id == run_id))
        if not run:
            raise ValueError(f"Training run '{run_id}' not found.")
        if run.status != "COMPLETED":
            raise ValueError(f"Run '{run_id}' is not in COMPLETED status (current: {run.status}).")

        # Register candidate in MLService
        cand_dir = Path(run.artifacts_dir)
        if not cand_dir.is_dir() or not (cand_dir / "model.joblib").is_file():
            raise FileNotFoundError(f"Model artifacts not found in {cand_dir}.")

        # Register and promote via MLService
        MLService.register_model(
            version_id=run.candidate_version,
            details={
                "version_id": run.candidate_version,
                "name": f"Adaptive Retrained Candidate ({run.candidate_version})",
                "model_version": run.candidate_version,
                "artifacts_dir": str(cand_dir),
                "algorithm": "XGBClassifier",
                "schema_version": "v2",
                "feature_count": 9,
                "role": "ACTIVE_PRIMARY",
                "description": f"Retrained on verified feedback data by {approved_by}.",
            },
        )

        promo_result = MLService.promote_model(
            version=run.candidate_version,
            reason=f"Administrator approval of training run {run_id} by {approved_by}",
        )

        now = datetime.now(timezone.utc)
        run.status = "PROMOTED"
        run.promoted_at = now
        run.promoted_by = approved_by
        db.commit()

        return {
            "status": "SUCCESSFULLY_PROMOTED",
            "run_id": run_id,
            "candidate_version": run.candidate_version,
            "promoted_at": now.isoformat(),
            "approved_by": approved_by,
            "promotion_details": promo_result,
        }

    @classmethod
    def rollback(cls, db: Session, reason: str = "Administrator rollback") -> Dict[str, Any]:
        result = MLService.rollback(reason=reason)
        return {
            "status": "ROLLBACK_SUCCESSFUL",
            "active_version": result["active_version"],
            "previous_version": result["previous_version"],
            "reason": reason,
        }
