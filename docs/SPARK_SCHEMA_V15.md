# Spark schema-explicit V15 experiment

The October 14 GPU notebook completed. Run 38528203806 failed to retrieve it
because its actual slug was `spark-external-v14-model-evaluation`. Recovery run
39059150187 verified evaluation SHA 863df1ba554cea2b95aa1796e8f29e3c2b60bf4e.

Both base and evidence V3 generated all 24 outputs (21 unique snippets). Both had
100% top-level key validity and hash copying, but 0/24 accepted evidence proposals.
All semantic fields had zero exact oracle agreement. Outputs used strings instead
of required nested objects/arrays; a literal `document.write` was called a source.
This is contract failure, not a general 0% XSS accuracy estimate. The retained raw
report has a metadata typo: FOUR repositories supply these selected fragments;
five repositories were in the earlier intake.

V15 is a separate candidate from the same pinned base. It preserves the 220 train
and 120 dev examples, family separation and targets. Its prompt explicitly defines
nested JSON types. The experimental recipe uses 3 epochs, learning rate 5e-5 and a
1536-token cutoff. Since several settings change, improvements cannot be attributed
to any one setting.

After training, the same notebook compares base and V15 on the existing 12-case
internal dev smoke test, with identical schema-explicit prompts and the existing
520-token generation cap. This exposed synthetic dev comparison is not independent
acceptance. V14 used different prompts and external cases; its numbers are not a
paired measure of V15 weight improvement. Use the in-run base/V15 comparison.

External V11–V14 snippets are excluded from training. No promotion occurs. Training
completion is distinct from evaluation success. The independently adjudicated
100 unsafe + 100 safe holdout remains incomplete.

Notebook: https://www.kaggle.com/code/dody2004/spark-schema-v15
Explicit launch marker: [launch-spark-schema-v15]
