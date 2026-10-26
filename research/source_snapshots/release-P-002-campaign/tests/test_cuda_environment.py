"""Discovery must fix the split-wheel warning without hiding real failures."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import warnings

from kryptos import cuda_environment as cuda
from kryptos.process_lifetime import launch_owned


class CudaEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.handles = len(cuda._DLL_HANDLES)
        cuda.prepare_cuda_environment.cache_clear(); cuda.load_cupy.cache_clear()

    def tearDown(self):
        for handle in cuda._DLL_HANDLES[self.handles:]: handle.close()
        del cuda._DLL_HANDLES[self.handles:]
        cuda.prepare_cuda_environment.cache_clear(); cuda.load_cupy.cache_clear()
        self.temp.cleanup()

    def wheel(self, name):
        return SimpleNamespace(version='14.2.0' if name=='cupy-cuda12x' else '12.9.0',
                               locate_file=lambda path: self.root/path)

    def install(self):
        for path in ('cuda_runtime/bin/cudart64_12.dll', 'cuda_runtime/include/cuda_runtime.h',
                     'cuda_nvrtc/bin/nvrtc64_120_0.dll', 'cuda_nvrtc/bin/nvrtc-builtins64_129.dll',
                     'cuda_nvrtc/include/nvrtc.h'):
            file=self.root/'nvidia'/path; file.parent.mkdir(parents=True,exist_ok=True); file.write_bytes(b'fixture')

    def test_registers_and_loads_actual_component_locations_once(self):
        self.install()
        def load(name):
            sub='cuda_runtime/bin/cudart64_12.dll' if name=='cudart' else 'cuda_nvrtc/bin/nvrtc64_120_0.dll'
            return SimpleNamespace(found_via='site-packages',abs_path=str(self.root/'nvidia'/sub))
        with patch.object(cuda.sys,'platform','win32'), patch.object(cuda.metadata,'distribution',side_effect=self.wheel), \
             patch.object(cuda.os,'add_dll_directory',create=True) as register, \
             patch.object(cuda.importlib,'import_module',return_value=SimpleNamespace(load_nvidia_dynamic_lib=load)):
            before=os.environ.copy()
            value=cuda.prepare_cuda_environment()
            self.assertEqual(value['mode'],'cuda12_component_wheels')
            self.assertEqual(set(value['libraries']),{'cudart','nvrtc'})
            self.assertEqual(register.call_count,2)
            self.assertIs(cuda.prepare_cuda_environment(),value)
            self.assertEqual(register.call_count,2)
            self.assertEqual(os.environ,before)

    def test_incomplete_wheels_keep_normal_diagnostics(self):
        with patch.object(cuda.sys,'platform','win32'), patch.object(cuda.metadata,'distribution',side_effect=self.wheel), \
             patch.object(cuda.os,'add_dll_directory',create=True) as register:
            self.assertEqual(cuda.prepare_cuda_environment()['mode'],'automatic')
            register.assert_not_called()

    def test_different_active_libraries_do_not_suppress_warning(self):
        self.install()
        loaded=SimpleNamespace(found_via='CUDA_PATH',abs_path=str(self.root/'other.dll'))
        with patch.object(cuda.sys,'platform','win32'), patch.object(cuda.metadata,'distribution',side_effect=self.wheel), \
             patch.object(cuda.os,'add_dll_directory',create=True), \
             patch.object(cuda.importlib,'import_module',return_value=SimpleNamespace(load_nvidia_dynamic_lib=lambda name:loaded)):
            self.assertEqual(cuda.prepare_cuda_environment()['mode'],'automatic')

    def test_registration_failure_keeps_normal_import_and_diagnostics(self):
        self.install()
        for failure_index in (0, 1):
            cuda.prepare_cuda_environment.cache_clear(); cuda.load_cupy.cache_clear()
            registrations = [Mock(), Mock()]
            registrations[failure_index] = OSError('registration failed')
            def importing(name):
                self.assertEqual(name, 'cupy')
                warnings.warn(cuda.PATH_WARNING, UserWarning)
                return 'normal import'
            with patch.object(cuda.sys,'platform','win32'), patch.object(cuda.metadata,'distribution',side_effect=self.wheel), \
                 patch.object(cuda.os,'add_dll_directory',create=True,side_effect=registrations), \
                 patch.object(cuda.importlib,'import_module',side_effect=importing), \
                 warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertEqual(cuda.load_cupy(), 'normal import')
                result = cuda.prepare_cuda_environment()
                self.assertEqual(result['mode'], 'automatic')
                self.assertIn('registration failed', result['discovery_error'])
                self.assertEqual(len(caught), 1)

    def test_only_exact_verified_warning_is_filtered_and_filter_is_restored(self):
        def importing(name):
            warnings.warn_explicit(cuda.PATH_WARNING,UserWarning,'environment.py',1,module='cupy._environment')
            warnings.warn_explicit('unrelated warning',UserWarning,'environment.py',2,module='cupy._environment')
            warnings.warn_explicit(cuda.PATH_WARNING,UserWarning,'other.py',3,module='other')
            return 'imported'
        for mode in ('cuda12_component_wheels','automatic'):
            cuda.load_cupy.cache_clear()
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always'); original=list(warnings.filters)
                with patch.object(cuda,'prepare_cuda_environment',return_value={'mode':mode}), \
                     patch.object(cuda.importlib,'import_module',side_effect=importing):
                    self.assertEqual(cuda.load_cupy(),'imported')
                self.assertEqual(warnings.filters,original)
            self.assertEqual(len(caught),2 if mode=='cuda12_component_wheels' else 3)

    def test_real_import_failure_is_not_silenced(self):
        with patch.object(cuda,'prepare_cuda_environment',return_value={'mode':'cuda12_component_wheels'}), \
             patch.object(cuda.importlib,'import_module',side_effect=ImportError('missing compiler dependency')):
            with self.assertRaisesRegex(ImportError,'missing compiler dependency'):cuda.load_cupy()

    @unittest.skipUnless(os.environ.get('KRYPTOS_TEST_CUDA')=='1','Actual CUDA is opt-in')
    def test_fresh_process_compiles_without_cuda_path_or_warning(self):
        env=os.environ.copy();env.pop('CUDA_PATH',None)
        out_path,err_path=self.root/'stdout.txt',self.root/'stderr.txt'
        with out_path.open('wb') as out, err_path.open('wb') as err:
            process=launch_owned([sys.executable,'-B','-c',
                'import json; from kryptos.accelerated import probe_backend; print(json.dumps(probe_backend()))'],
                env=env,stdout=out,stderr=err)
            try:
                returncode=process.wait(timeout=30)
            finally:
                process.close()
        stderr=err_path.read_text()
        self.assertEqual(returncode,0,stderr)
        self.assertNotIn(cuda.PATH_WARNING,stderr)
        value=json.loads(out_path.read_text())['cuda']
        self.assertTrue(value['ready'],value)
        self.assertTrue(value['compiled_kernel_verified'])
        if sys.platform=='win32':self.assertEqual(value['environment']['mode'],'cuda12_component_wheels')


if __name__=='__main__':unittest.main()
