"""Shared synthetic CPU runtime for local evaluator and subprocess checks."""

import json
import os
import sys
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType, SimpleNamespace

DIGEST = "a" * 64
RISK_TOKEN = 50000


def install_runtime(
    monkeypatch, tmp_path, *, risk_text=None, stub_verification=True
) -> SimpleNamespace:
    from jev_reflex import local_evaluator as local

    class FakeTokenizer:
        def no_padding(self):
            pass

        def no_truncation(self):
            pass

        def token_to_id(self, token):
            return 104 if token == "[MASK]" else None

        def encode(self, value, *, add_special_tokens):
            assert not add_special_tokens
            return SimpleNamespace(
                ids=[
                    RISK_TOKEN if risk_text and risk_text in word else 200 + len(word)
                    for word in value.split()
                ]
            )

    class FakeORTSession:
        def __init__(self, graph, *, sess_options, providers):
            assert graph == b"onnx"
            assert providers == ["CPUExecutionProvider"]
            assert sess_options.use_deterministic_compute
            state.sessions += 1
            if risk_text is not None:
                assert state.sessions == 1

        def get_inputs(self):
            return [
                SimpleNamespace(name=name, type=dtype, shape=shape)
                for name, dtype, shape in (
                    ("input_ids", "tensor(int64)", ["batch", "tokens"]),
                    ("attention_mask", "tensor(int64)", ["batch", "tokens"]),
                    ("marker_pos", "tensor(int64)", ["batch", "options"]),
                    ("marker_mask", "tensor(bool)", ["batch", "options"]),
                    ("qtype", "tensor(int64)", ["batch"]),
                )
            ]

        def get_outputs(self):
            return [
                SimpleNamespace(name=name, type="tensor(float)", shape=["batch", "options"])
                for name in ("logits", "act_logits")
            ]

        def run(self, output_names, feeds):
            assert output_names == ["logits"]
            state.feeds = feeds
            state.calls += 1
            logits = [
                ([0.0, 20.0] if RISK_TOKEN in row else [20.0, 0.0])
                if risk_text is not None
                else list(state.logits)
                for row in feeds["input_ids"]
            ]
            return [SimpleNamespace(shape=(len(logits), 2), tolist=lambda: logits)]

    state = SimpleNamespace(sessions=0, calls=0, feeds=None, logits=(0.0, 2.0))
    ort = ModuleType("onnxruntime")
    ort.__spec__ = ModuleSpec("onnxruntime", loader=None)
    ort.SessionOptions = lambda: SimpleNamespace(add_session_config_entry=lambda *_: None)
    ort.InferenceSession = FakeORTSession
    ort.ExecutionMode = SimpleNamespace(ORT_SEQUENTIAL=0)
    numpy = ModuleType("numpy")
    numpy.asarray = lambda values, **_kwargs: values
    numpy.int64 = int
    numpy.bool_ = bool
    tokenizers = ModuleType("tokenizers")
    tokenizers.Tokenizer = SimpleNamespace(from_str=lambda _: FakeTokenizer())
    for module in (ort, tokenizers, numpy):
        monkeypatch.setitem(sys.modules, module.__name__, module)
    verified = SimpleNamespace(
        model_id="ollaya-dev/coba-68m-ternary",
        graph=tmp_path / "model.onnx",
        tokenizer=tmp_path / "tokenizer.json",
        decision=tmp_path / "decision.json",
        calibration=tmp_path / "calibration.json",
        digest=DIGEST,
        read_asset=Path.read_bytes,
    )
    verified.graph.write_bytes(b"onnx")
    verified.tokenizer.write_text("{}")
    verified.decision.write_text(
        json.dumps(
            {
                "engine": "onnx",
                "family": "laya",
                "layout": "laya-markers-v1",
                "max_len": 512,
                "head_max_len": 192,
                "min_markers": 2,
                "special_tokens": {
                    "cls": 101,
                    "sep": 102,
                    "pad": 103,
                    "mask": 104,
                    "mask_text": "[MASK]",
                },
                "inputs": ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"],
                "outputs": ["logits", "act_logits"],
            }
        )
    )
    verified.calibration.write_text('{"temperature":[1,1,0.5],"temperature_by_options":{}}')

    def verify_model(model_id, model_dir):
        if risk_text is not None:
            assert "TYPESAFE_API_KEY" not in os.environ
            assert model_id == verified.model_id
            assert Path(model_dir) == tmp_path
        return verified

    if stub_verification:
        monkeypatch.setattr(local, "verify_model", verify_model)
    state.verified = verified
    return state
