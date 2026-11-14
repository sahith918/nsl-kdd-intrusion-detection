# Network Intrusion Detection with Machine Learning

A Random Forest classifier that labels network connections as **normal** or **attack**, trained on the NSL-KDD dataset. Runs on a normal laptop CPU in about a minute.

## Results

Evaluated on the official `KDDTest+` set (22,544 connections). The test set deliberately includes attack types that never appear in training, so it measures generalization to unseen attacks.

The model outputs an attack probability, and a decision threshold turns that into a yes/no alert. Lowering the threshold catches more attacks but raises more false alarms.

| Threshold | Accuracy | Attack recall | Attack precision | Missed attacks | False alarms |
|---|---|---|---|---|---|
| 0.5 (default) | 77% | 0.61 | 0.97 | 5,031 | 266 |
| 0.4 | 79% | 0.66 | 0.97 | 4,372 | 275 |
| 0.3 | 82% | 0.71 | 0.97 | 3,753 | 303 |
| 0.2 | 85% | 0.77 | 0.95 | 2,895 | 475 |
| 0.15 | 85% | 0.80 | 0.92 | 2,565 | 872 |
| 0.1 | 87% | 0.84 | 0.92 | 2,053 | 929 |
| **0.05 (used)** | **91%** | **0.92** | **0.92** | **1,075** | **1,017** |

Going from the default 0.5 to 0.05 cuts missed attacks from 5,031 to 1,075 (about 79% fewer) while false alarms rise from 266 to 1,017. In intrusion detection a missed attack is usually costlier than a false alarm, so a low threshold makes sense. The right value in practice depends on how many alerts an analyst can handle: at 0.05, about 10.5% of normal traffic is flagged.

### Detailed results at threshold 0.05

```
              precision    recall  f1-score   support

      normal       0.89      0.90      0.89      9711
      attack       0.92      0.92      0.92     12833

    accuracy                           0.91     22544
   macro avg       0.91      0.91      0.91     22544
weighted avg       0.91      0.91      0.91     22544
```

Confusion matrix (rows = actual, columns = predicted):

|  | Predicted normal | Predicted attack |
|---|---|---|
| **Actual normal** | 8,694 | 1,017 |
| **Actual attack** | 1,075 | 11,758 |

### Top 10 most important features

| Feature | Importance |
|---|---|
| `src_bytes` | 0.169 |
| `dst_bytes` | 0.083 |
| `flag_SF` | 0.069 |
| `dst_host_same_srv_rate` | 0.057 |
| `dst_host_srv_count` | 0.057 |
| `logged_in` | 0.052 |
| `same_srv_rate` | 0.050 |
| `dst_host_srv_serror_rate` | 0.046 |
| `diff_srv_rate` | 0.040 |
| `protocol_type_icmp` | 0.030 |

## Run it

1. Download the data: `kaggle datasets download -d hassan06/nslkdd --unzip`
2. Install dependencies: `pip install -r requirements.txt`
3. Run: `python nsl_kdd_ids.py`

To change the operating point, edit `THRESHOLD` at the top of the script.

## Limitations

- **The threshold was chosen by sweeping values on the test set**, so the reported results are somewhat optimistic. A cleaner setup would choose it on a separate validation split and report the test score once.
- NSL-KDD is an old, synthetic benchmark. Scores here do not reflect performance on modern real-world traffic.
- Binary classification only. It does not say which type of attack was detected.

## Possible next steps

- Gradient boosting (XGBoost) comparison
- Multi-class detection (DoS, Probe, R2L, U2R)
- SHAP explanations for individual alerts
- Streamlit app for uploading connection records
- Evaluate on CIC-IDS2017

## Data

NSL-KDD dataset, available on Kaggle (`hassan06/nslkdd`). Original data from the Canadian Institute for Cybersecurity.
