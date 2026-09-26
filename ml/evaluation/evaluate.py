"""
Model Evaluation and Metrics Reporting
=======================================
Computes honest multi-class classification metrics including accuracy, precision,
recall, F1-scores, support, and confusion matrix on holdout sets.
"""

from typing import Any, Dict, List, Union
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def evaluate_model(
    y_true: Union[np.ndarray, List[str]],
    y_pred: Union[np.ndarray, List[str]],
    labels: List[str],
) -> Dict[str, Any]:
    """
    Compute comprehensive evaluation metrics for multi-class classification.

    Parameters
    ----------
    y_true : array-like
        True ground truth labels.
    y_pred : array-like
        Model predicted class labels.
    labels : list of str
        Complete ordered list of target class names.

    Returns
    -------
    dict
        Structured evaluation metrics.
    """
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro = float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    cm_list = cm.tolist()

    report_dict = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    per_class_metrics = {}
    for label in labels:
        if label in report_dict:
            per_class_metrics[label] = {
                "precision": round(report_dict[label]["precision"], 4),
                "recall": round(report_dict[label]["recall"], 4),
                "f1_score": round(report_dict[label]["f1-score"], 4),
                "support": int(report_dict[label]["support"]),
            }

    return {
        "overall": {
            "accuracy": round(acc, 4),
            "macro_precision": round(prec_macro, 4),
            "macro_recall": round(rec_macro, 4),
            "macro_f1": round(f1_macro, 4),
            "weighted_precision": round(prec_weighted, 4),
            "weighted_recall": round(rec_weighted, 4),
            "weighted_f1": round(f1_weighted, 4),
            "total_samples": len(y_true),
        },
        "per_class": per_class_metrics,
        "labels": labels,
        "confusion_matrix": cm_list,
    }


def format_evaluation_report(metrics: Dict[str, Any]) -> str:
    """
    Format evaluation metrics into a clean text representation.
    """
    overall = metrics["overall"]
    per_class = metrics["per_class"]
    labels = metrics["labels"]
    cm = metrics["confusion_matrix"]

    lines = [
        "==================================================",
        "          ML MODEL EVALUATION REPORT",
        "==================================================",
        f"Total Samples Evaluated: {overall['total_samples']}",
        f"Overall Accuracy:        {overall['accuracy'] * 100:.2f}%",
        f"Macro F1-Score:          {overall['macro_f1']:.4f}",
        f"Weighted F1-Score:       {overall['weighted_f1']:.4f}",
        f"Macro Precision:         {overall['macro_precision']:.4f}",
        f"Macro Recall:            {overall['macro_recall']:.4f}",
        "--------------------------------------------------",
        "Per-Class Performance Breakdown:",
        f"{'Class':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}",
        "-" * 70,
    ]

    for label in labels:
        p = per_class.get(label, {})
        lines.append(
            f"{label:<22} | {p.get('precision', 0.0):<10.4f} | {p.get('recall', 0.0):<10.4f} | {p.get('f1_score', 0.0):<10.4f} | {p.get('support', 0):<8}"
        )

    lines.extend([
        "--------------------------------------------------",
        "Confusion Matrix (Rows: Ground Truth, Cols: Predicted):",
        f"Labels: {', '.join(labels)}",
    ])

    for i, row in enumerate(cm):
        row_str = "  ".join(f"{val:>6}" for val in row)
        lines.append(f"  [{labels[i]:<20}] -> {row_str}")

    lines.append("==================================================")
    return "\n".join(lines)
