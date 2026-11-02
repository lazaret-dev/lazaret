"""Write python/tests/fixtures/model_files/: benign model files written by the real libraries, the precision review
of FP-MODEL-FILES (Oct 21). Each one was a false positive of the first reader (a datetime's ZoneInfo, pandas 3's
Arrow-backed arrays, pyarrow's own objects, dateutil's and pytz's zones, an Arrow extension type, a Hugging Face
dataset, pandas' zip-compressed pickle) and must stay quiet: tests/scanner/test_review_model_precision.py reads them.

Ordinary data a user would save; the text in them is inert (reserved hosts, made-up paths). The tests read the bytes,
never load them. Needs a venv with pandas 3, pyarrow, python-dateutil, pytz and datasets (no torch):

    python -I scripts/make_model_fixtures.py [OUT]
"""
import datetime
import decimal
import os
import pickle
import sys
import zoneinfo

import dateutil.tz
import pandas as pd
import pyarrow as pa
import pytz

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "python", "tests", "fixtures", "model_files")
os.makedirs(OUT, exist_ok=True)


def put(name, obj, protocols=(2, 5)):
    for p in protocols:
        with open(os.path.join(OUT, f"{name}.p{p}.pkl"), "wb") as fh:
            pickle.dump(obj, fh, protocol=p)


chicago = zoneinfo.ZoneInfo("America/Chicago")
# a datetime with its zone: ZoneInfo pickles as getattr(ZoneInfo, '_unpickle')(key, 1)
put("zoneinfo_datetime", {"started": datetime.datetime(2026, 10, 21, 9, 30, tzinfo=chicago),
                          "zones": [zoneinfo.ZoneInfo("Europe/Paris"), chicago]})

# pandas 3: strings are Arrow-backed (pyarrow's _restore_array, type_for_alias, py_buffer), zones are zoneinfo's
frame = pd.DataFrame({
    "text": ["a", "https://data.invalid/x", None],
    "n": [1, 2, 3],
    "x": [0.5, None, 1.5],
    "when": pd.date_range("2026-10-21", periods=3, freq="D", tz="America/Chicago"),
    "kind": pd.Categorical(["a", "b", "a"]),
    "count": pd.array([1, None, 3], dtype="Int64"),
    "period": pd.period_range("2026-10", periods=3, freq="M"),
})
put("pandas_frame", frame)
frame.to_pickle(os.path.join(OUT, "pandas_frame.pkl.zip"))         # (zip compression, by the name)

# pandas' ArrowDtype columns: lists, a dictionary, a struct, a timestamp, a decimal
arrow = pd.DataFrame({
    "lists": pd.Series([[1, 2], [], None], dtype=pd.ArrowDtype(pa.list_(pa.int64()))),
    "labels": pd.Series(pa.array(["x", "y", "x"]).dictionary_encode(), dtype=pd.ArrowDtype(
        pa.dictionary(pa.int32(), pa.string()))),
    "pairs": pd.Series([{"a": 1, "b": "u"}, {"a": 2, "b": "v"}, None],
                       dtype=pd.ArrowDtype(pa.struct([("a", pa.int64()), ("b", pa.string())]))),
    "ts": pd.Series(pd.date_range("2026-01-01", periods=3, tz="UTC")).astype(pd.ArrowDtype(pa.timestamp("us", "UTC"))),
    "money": pd.Series([decimal.Decimal("1.50"), None, decimal.Decimal("2.25")], dtype=pd.ArrowDtype(pa.decimal128(10, 2))),
})
put("pandas_arrow", arrow)

# pyarrow's own objects: array, chunked array, table, record batch, schema, field, type, scalar, buffer, an
# extension type (pandas' period type, by its deserializer)
arr = pa.array([1, 2, None])
table = pa.table({"a": arr, "b": pa.array(["u", "v", "w"])}, metadata={"source": "made-up"})
put("pyarrow_objects", {
    "array": arr, "chunked": pa.chunked_array([arr, arr]), "table": table, "batch": table.to_batches()[0],
    "schema": table.schema, "field": pa.field("a", pa.int64(), nullable=False), "type": pa.map_(pa.string(), pa.int32()),
    "scalar": pa.scalar(3.5), "buffer": pa.py_buffer(b"abc"), "dict": pa.array(["x", "y"]).dictionary_encode(),
    "period": pa.array(pd.period_range("2026-10", periods=2, freq="M").array),
})

# dateutil's and pytz's zones
put("dateutil_pytz", {
    "tzfile": pd.Series(pd.date_range("2026-10-21", periods=2, tz=dateutil.tz.gettz("Asia/Tokyo"))),
    "zones": [dateutil.tz.tzutc(), dateutil.tz.tzoffset("X", 3600), dateutil.tz.tzlocal(),
              dateutil.tz.tzstr("EST5EDT"), dateutil.tz.tzrange("EST", -18000, "EDT")],
    "pytz": [pytz.timezone("America/Chicago"), pytz.utc, pytz.FixedOffset(60),
             pytz.timezone("America/Chicago").localize(datetime.datetime(2026, 10, 21))],
})

# a Hugging Face dataset (its Arrow table: pyarrow's schema, field, chunked_array, _reconstruct_table)
try:
    import datasets
except ImportError:
    datasets = None
if datasets is not None:
    ds = datasets.Dataset.from_dict({"text": ["a", "b"], "label": [0, 1]}, features=datasets.Features(
        {"text": datasets.Value("string"), "label": datasets.ClassLabel(names=["neg", "pos"])}))
    put("hf_dataset", ds, protocols=(4,))
print("written to", OUT)
