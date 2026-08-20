"""
Tracer-Risk — dimension data for testing and demo.
Synthetic embeddings for public health risk analysis.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
SAMPLE_EXPOSURES = [
    {
        "id": "lack_sanitation",
        "name": "Lack of basic sanitation",
        "category": "environmental",
        "vector": [0.12, -0.34, 0.56, -0.12, 0.34, -0.56, 0.12, -0.34,
                   0.56, -0.12, 0.34, -0.56, 0.12, -0.34, 0.56, -0.12],
        "metadata": {"source": "IBGE", "year": 2024},
    },
    {
        "id": "smoking_rate",
        "name": "Smoking rate",
        "category": "behavioral",
        "vector": [-0.23, 0.45, -0.67, 0.23, -0.45, 0.67, -0.23, 0.45,
                   -0.67, 0.23, -0.45, 0.67, -0.23, 0.45, -0.67, 0.23],
        "metadata": {"source": "DATASUS", "year": 2024},
    },
    {
        "id": "pesticide_exposure",
        "name": "Pesticide exposure",
        "category": "chemical",
        "vector": [0.34, -0.12, 0.78, -0.34, 0.12, -0.78, 0.34, -0.12,
                   0.78, -0.34, 0.12, -0.78, 0.34, -0.12, 0.78, -0.34],
        "metadata": {"source": "ANVISA", "year": 2024},
    },
    {
        "id": "industrial_chemicals",
        "name": "Industrial chemical exposure",
        "category": "chemical",
        "vector": [-0.45, 0.23, -0.89, 0.45, -0.23, 0.89, -0.45, 0.23,
                   -0.89, 0.45, -0.23, 0.89, -0.45, 0.23, -0.89, 0.45],
        "metadata": {"source": "Ministério do Trabalho", "year": 2024},
    },
    {
        "id": "obesity_rate",
        "name": "Obesity rate",
        "category": "behavioral",
        "vector": [0.56, -0.78, 0.12, -0.56, 0.78, -0.12, 0.56, -0.78,
                   0.12, -0.56, 0.78, -0.12, 0.56, -0.78, 0.12, -0.56],
        "metadata": {"source": "DATASUS", "year": 2024},
    },
]

SAMPLE_OUTCOMES = [
    {
        "id": "diarrhea_hospitalizations",
        "name": "Diarrhea-related hospitalizations",
        "category": "admission",
        "vector": [0.45, -0.23, 0.12, -0.45, 0.23, -0.12, 0.45, -0.23,
                   0.12, -0.45, 0.23, -0.12, 0.45, -0.23, 0.12, -0.45],
        "metadata": {"source": "DATASUS/SIH", "year": 2024},
    },
    {
        "id": "cancer_treatment_costs",
        "name": "Cancer treatment costs",
        "category": "hospital_cost",
        "vector": [-0.12, 0.34, -0.56, 0.12, -0.34, 0.56, -0.12, 0.34,
                   -0.56, 0.12, -0.34, 0.56, -0.12, 0.34, -0.56, 0.12],
        "metadata": {"source": "DATASUS/APAC", "year": 2024},
    },
    {
        "id": "cardiovascular_mortality",
        "name": "Cardiovascular mortality",
        "category": "mortality",
        "vector": [0.67, -0.89, 0.23, -0.67, 0.89, -0.23, 0.67, -0.89,
                   0.23, -0.67, 0.89, -0.23, 0.67, -0.89, 0.23, -0.67],
        "metadata": {"source": "DATASUS/SIM", "year": 2024},
    },
    {
        "id": "diabetes_medication",
        "name": "Diabetes medication expenditure",
        "category": "medication",
        "vector": [-0.34, 0.56, -0.78, 0.34, -0.56, 0.78, -0.34, 0.56,
                   -0.78, 0.34, -0.56, 0.78, -0.34, 0.56, -0.78, 0.34],
        "metadata": {"source": "DATASUS/CEAF", "year": 2024},
    },
    {
        "id": "respiratory_admissions",
        "name": "Respiratory disease admissions",
        "category": "admission",
        "vector": [0.89, -0.45, 0.67, -0.89, 0.45, -0.67, 0.89, -0.45,
                   0.67, -0.89, 0.45, -0.67, 0.89, -0.45, 0.67, -0.89],
        "metadata": {"source": "DATASUS/SIH", "year": 2024},
    },
]
