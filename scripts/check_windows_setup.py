"""Check the running project interpreter, pinned wheels, actual DLLs and kernel."""
import argparse
import ctypes
from importlib import metadata
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def check(label, operation):
    try:
        detail = operation()
        print(f"PASS {label}: {detail}")
        return True
    except Exception as error:
        print(f"FAIL {label}: {error}")
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpu", action="store_true")
    parser.add_argument("--sat", action="store_true")
    args = parser.parse_args()
    print(f"Python {sys.version.split()[0]} at {sys.executable}")
    from importlib import import_module
    passed = check("CPU dashboard import", lambda: import_module("kryptos.app").__file__)
    if args.sat:
        passed &= check("Z3", lambda: import_module("z3").get_version_string())
    if not args.gpu:
        return int(not passed)

    def driver():
        try:
            lib = ctypes.WinDLL("nvcuda.dll")
        except OSError as error:
            raise RuntimeError("Missing NVIDIA display driver (nvcuda.dll could not load)") from error
        code = lib.cuInit(0)
        if code:
            raise RuntimeError(f"cuInit returned {code}")
        version = ctypes.c_int()
        code = lib.cuDriverGetVersion(ctypes.byref(version))
        if code:
            raise RuntimeError(f"cuDriverGetVersion returned {code}")
        return version.value

    driver_ok = check("NVIDIA display driver", driver)
    passed &= driver_ok
    wheels_ok = True
    for line in (ROOT / "requirements-gpu.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, version = line.split("==")

        def pinned():
            installed = metadata.version(name)
            if installed != version:
                raise RuntimeError(f"expected {version}, installed {installed}")
            return installed

        wheels_ok &= check(name, pinned)
    from kryptos.cuda_environment import prepare_cuda_environment
    layout = prepare_cuda_environment()
    for library in ("cudart", "nvrtc"):
        def library_path():
            found = layout["libraries"].get(library)
            if not found:
                raise RuntimeError(layout.get("discovery_note") or layout.get("discovery_error") or "wheel DLL missing")
            return found

        wheels_ok &= check(library + " wheel DLL", library_path)

    driver_incompatible = False

    def kernel():
        nonlocal driver_incompatible
        from kryptos.launcher import bounded_gpu_probe
        import os
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as scratch:
            # Exercise NVRTC compilation from cold cache as well as execution.
            env = dict(os.environ, TEMP=scratch, TMP=scratch, CUPY_CACHE_DIR=scratch)
            result = bounded_gpu_probe(sys.executable, env, scratch, timeout=120)["cuda"]
        if not result.get("compiled_kernel_verified"):
            driver_incompatible = bool(result.get("driver_action_required"))
            raise RuntimeError(result.get("error", "CUDA readiness kernel failed"))
        return f"{result['devices'][0]['name']}, compiled readiness result 42"

    passed &= check("CUDA compile, launch and readback", kernel)
    passed &= wheels_ok
    if not driver_ok or driver_incompatible:
        print("Missing or unusable NVIDIA display driver. Get the driver with this PowerShell command:")
        print("Start-Process 'https://www.nvidia.com/Download/index.aspx'")
    elif not passed:
        print("Repair the CUDA profile by running .\\Setup.cmd -Gpu")
        if not wheels_ok:
            return 2
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
