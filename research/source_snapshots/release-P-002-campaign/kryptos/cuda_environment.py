"""Resolve Windows CUDA component wheels before importing CuPy.

CUDA 12 wheels have separate runtime and NVRTC roots. CuPy 14 recognizes
their libraries, but still warns that a single Toolkit root is absent.
"""
from functools import lru_cache
import importlib
from importlib import metadata
import os
from pathlib import Path
import re
import sys
import threading
import warnings

PATH_WARNING = 'CUDA path could not be detected. Set CUDA_PATH environment variable if CuPy fails to load.'
_DLL_HANDLES = []  # Windows search-directory registrations must remain alive.
_IMPORT_LOCK = threading.RLock()


@lru_cache(maxsize=1)
def prepare_cuda_environment():
    result = {'mode': 'automatic', 'configured_cuda_path': os.environ.get('CUDA_PATH'),
              'dll_directories': [], 'libraries': {}}
    if sys.platform != 'win32':
        return result
    try:
        cupy = metadata.distribution('cupy-cuda12x')
        runtime = metadata.distribution('nvidia-cuda-runtime-cu12')
        nvrtc = metadata.distribution('nvidia-cuda-nvrtc-cu12')
    except metadata.PackageNotFoundError:
        return result
    if not (cupy.version.startswith('14.') and runtime.version.startswith('12.') and nvrtc.version.startswith('12.')):
        return result
    runtime_root = Path(runtime.locate_file('nvidia/cuda_runtime')).resolve()
    nvrtc_root = Path(nvrtc.locate_file('nvidia/cuda_nvrtc')).resolve()
    expected = {'cudart': runtime_root/'bin/cudart64_12.dll',
                'nvrtc': nvrtc_root/'bin/nvrtc64_120_0.dll'}
    required = [*expected.values(), runtime_root/'include/cuda_runtime.h', nvrtc_root/'include/nvrtc.h']
    if not all(p.is_file() for p in required) or not any(p.is_file() for p in (nvrtc_root/'bin').glob('nvrtc-builtins64_12*.dll')):
        result['discovery_note'] = 'CUDA 12 component installation is incomplete; using normal CuPy diagnostics.'
        return result
    try:
        for directory in dict.fromkeys(str(p.parent) for p in expected.values()):
            _DLL_HANDLES.append(os.add_dll_directory(directory))
            result['dll_directories'].append(directory)
        pathfinder = importlib.import_module('cuda.pathfinder')
        for name, path in expected.items():
            loaded = pathfinder.load_nvidia_dynamic_lib(name)
            if loaded.found_via != 'site-packages' or Path(loaded.abs_path).resolve() != path:
                result['discovery_note'] = 'Active CUDA libraries differ from the component wheels; using normal CuPy diagnostics.'
                return result
            result['libraries'][name] = str(path)
    except (ImportError, OSError, RuntimeError) as error:
        result['discovery_error'] = str(error)
        return result
    result.update(mode='cuda12_component_wheels', toolkit_root=None,
                  package_versions={'cupy': cupy.version, 'runtime': runtime.version, 'nvrtc': nvrtc.version})
    return result


@lru_cache(maxsize=1)
def load_cupy():
    with _IMPORT_LOCK:
        environment = prepare_cuda_environment()
        if environment['mode'] != 'cuda12_component_wheels':
            return importlib.import_module('cupy')
        # Only this verified split-layout warning is inapplicable. Every other
        # warning and any import/driver/compiler exception retains its behavior.
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message=re.escape(PATH_WARNING)+r'\Z',
                                    category=UserWarning, module=r'cupy\._environment\Z')
            return importlib.import_module('cupy')
