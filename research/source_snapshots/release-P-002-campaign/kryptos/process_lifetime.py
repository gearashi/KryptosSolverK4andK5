"""Own worker descendants as well as a Windows virtualenv redirector.

Windows10+: CreateProcess atomically assigns a non-inherited kill-on-close Job
Object using PROC_THREAD_ATTRIBUTE_JOB_LIST. Only duplicated stdio handles are
inherited. No PID enumeration, launcher/interpreter race, or stale PID kill.
POSIX uses a new session/process group. This private API supports file/DEVNULL
stdio only, which is all the file-protocol workers require.
"""
import math
import os
import signal
import subprocess
import time


def launch_owned(args,*,cwd=None,env=None,stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0):
    if os.name=="nt":
        return _WindowsProcess(args,cwd,env,stdin,stdout,stderr,creationflags)
    return _PosixProcess(args,cwd,env,stdin,stdout,stderr)


class _PosixProcess:
    def __init__(self,args,cwd,env,stdin,stdout,stderr):
        self.process=subprocess.Popen(args,cwd=cwd,env=env,stdin=stdin,stdout=stdout,stderr=stderr,start_new_session=True)
        self.pid=self.process.pid
        self._closed=False
    @property
    def returncode(self):
        return self.process.returncode
    def poll(self):
        return self.process.poll()
    def wait(self,timeout=None):
        return self.process.wait(timeout=timeout)
    def terminate(self):
        if self._closed:
            return
        try:
            os.killpg(self.pid,signal.SIGTERM)
        except ProcessLookupError:
            pass
    def kill(self):
        if self._closed:
            return
        try:
            os.killpg(self.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
    def close(self):
        if self._closed:
            return
        self.kill()
        self.wait(timeout=3)
        self._closed=True


if os.name=="nt":
    import ctypes as C
    from ctypes import wintypes as W
    import msvcrt

    class _BasicLimits(C.Structure):
        _fields_=[("process_time",C.c_longlong),("job_time",C.c_longlong),("flags",W.DWORD),
            ("min_working",C.c_size_t),("max_working",C.c_size_t),("processes",W.DWORD),
            ("affinity",C.c_size_t),("priority",W.DWORD),("scheduling",W.DWORD)]
    class _IoCounters(C.Structure):
        _fields_=[(name,C.c_ulonglong) for name in ("read","write","other","read_bytes","write_bytes","other_bytes")]
    class _ExtendedLimits(C.Structure):
        _fields_=[("basic",_BasicLimits),("io",_IoCounters),("process_memory",C.c_size_t),
            ("job_memory",C.c_size_t),("peak_process",C.c_size_t),("peak_job",C.c_size_t)]
    class _Accounting(C.Structure):
        _fields_=[(name,C.c_longlong) for name in ("user","kernel","period_user","period_kernel")]+[
            (name,W.DWORD) for name in ("faults","total","active","terminated")]
    class _Startup(C.Structure):
        _fields_=[("cb",W.DWORD),("reserved",W.LPWSTR),("desktop",W.LPWSTR),("title",W.LPWSTR)]+[
            (name,W.DWORD) for name in ("x","y","xsize","ysize","xchars","ychars","fill","flags")]+[
            ("show",W.WORD),("reserved_bytes",W.WORD),("reserved_ptr",C.c_void_p),
            ("stdin",W.HANDLE),("stdout",W.HANDLE),("stderr",W.HANDLE)]
    class _StartupEx(C.Structure):
        _fields_=[("startup",_Startup),("attributes",C.c_void_p)]
    class _ProcessInformation(C.Structure):
        _fields_=[("process",W.HANDLE),("thread",W.HANDLE),("pid",W.DWORD),("tid",W.DWORD)]

    K=C.WinDLL("kernel32",use_last_error=True)
    def _api(name,restype,argtypes):
        function=getattr(K,name)
        function.restype=restype
        function.argtypes=argtypes
        return function
    _api("CreateJobObjectW",W.HANDLE,[C.c_void_p,W.LPCWSTR])
    _api("SetInformationJobObject",W.BOOL,[W.HANDLE,C.c_int,C.c_void_p,W.DWORD])
    _api("QueryInformationJobObject",W.BOOL,[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p])
    _api("TerminateJobObject",W.BOOL,[W.HANDLE,W.UINT])
    _api("CloseHandle",W.BOOL,[W.HANDLE])
    _api("GetCurrentProcess",W.HANDLE,[])
    _api("DuplicateHandle",W.BOOL,[W.HANDLE,W.HANDLE,W.HANDLE,C.POINTER(W.HANDLE),W.DWORD,W.BOOL,W.DWORD])
    _api("InitializeProcThreadAttributeList",W.BOOL,[C.c_void_p,W.DWORD,W.DWORD,C.POINTER(C.c_size_t)])
    _api("UpdateProcThreadAttribute",W.BOOL,[C.c_void_p,W.DWORD,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p])
    _api("DeleteProcThreadAttributeList",None,[C.c_void_p])
    _api("CreateProcessW",W.BOOL,[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,C.c_void_p,W.LPCWSTR,C.c_void_p,C.POINTER(_ProcessInformation)])
    _api("WaitForSingleObject",W.DWORD,[W.HANDLE,W.DWORD])
    _api("GetExitCodeProcess",W.BOOL,[W.HANDLE,C.POINTER(W.DWORD)])

    def _check(value):
        if not value:
            raise C.WinError(C.get_last_error())
        return value

    class _WindowsProcess:
        def __init__(self,args,cwd,env,stdin,stdout,stderr,creationflags):
            self.args=list(map(str,args))
            self.returncode=None
            self.process=None
            self.job=None
            duplicated=[]
            attributes=None
            initialized=False
            null=None
            try:
                self.job=_check(K.CreateJobObjectW(None,None))
                limits=_ExtendedLimits()
                limits.basic.flags=0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                _check(K.SetInformationJobObject(self.job,9,C.byref(limits),C.sizeof(limits)))
                current=K.GetCurrentProcess()
                null=open(os.devnull,"r+b",buffering=0)
                for stream in (stdin,stdout,stderr):
                    if stream==subprocess.DEVNULL:
                        descriptor=null.fileno()
                    elif hasattr(stream,"fileno"):
                        descriptor=stream.fileno()
                    elif isinstance(stream,int) and stream>=0:
                        descriptor=stream
                    else:
                        raise ValueError("owned process stdio requires a file descriptor or DEVNULL")
                    duplicate=W.HANDLE()
                    _check(K.DuplicateHandle(current,msvcrt.get_osfhandle(descriptor),current,C.byref(duplicate),0,True,2))
                    duplicated.append(duplicate.value)
                size=C.c_size_t()
                K.InitializeProcThreadAttributeList(None,2,0,C.byref(size))
                attributes=C.create_string_buffer(size.value)
                _check(K.InitializeProcThreadAttributeList(attributes,2,0,C.byref(size)))
                initialized=True
                handles=(W.HANDLE*3)(*duplicated)
                jobs=(W.HANDLE*1)(self.job)
                _check(K.UpdateProcThreadAttribute(attributes,0,0x20002,handles,C.sizeof(handles),None,None))
                _check(K.UpdateProcThreadAttribute(attributes,0,0x2000D,jobs,C.sizeof(jobs),None,None))
                startup=_StartupEx()
                startup.startup.cb=C.sizeof(startup)
                startup.startup.flags=0x100  # STARTF_USESTDHANDLES
                startup.startup.stdin,startup.startup.stdout,startup.startup.stderr=duplicated
                startup.attributes=C.addressof(attributes)
                info=_ProcessInformation()
                environment=None if env is None else C.create_unicode_buffer("\0".join(f"{key}={value}" for key,value in sorted(env.items(),key=lambda pair:pair[0].upper()))+"\0\0")
                command=C.create_unicode_buffer(subprocess.list2cmdline(self.args))
                # Atomic job assignment avoids a create/assign/suspend crash gap.
                flags=creationflags|0x00080000|0x00000400|0x08000000
                _check(K.CreateProcessW(None,command,None,None,True,flags,environment,str(cwd) if cwd else None,C.byref(startup),C.byref(info)))
                self.process=info.process
                self.pid=info.pid
                K.CloseHandle(info.thread)
            except BaseException:
                self.close()
                raise
            finally:
                if initialized:
                    K.DeleteProcThreadAttributeList(attributes)
                for handle in duplicated:
                    K.CloseHandle(handle)
                if null is not None:
                    null.close()

        def poll(self):
            if self.returncode is not None:
                return self.returncode
            status=K.WaitForSingleObject(self.process,0)
            if status==258:
                return None
            if status!=0:
                raise C.WinError(C.get_last_error())
            code=W.DWORD()
            _check(K.GetExitCodeProcess(self.process,C.byref(code)))
            self.returncode=code.value
            return self.returncode

        def wait(self,timeout=None):
            milliseconds=0xFFFFFFFF if timeout is None else min(0xFFFFFFFE,max(0,math.ceil(timeout*1000)))
            status=K.WaitForSingleObject(self.process,milliseconds)
            if status==258:
                raise subprocess.TimeoutExpired(self.args,timeout)
            if status!=0:
                raise C.WinError(C.get_last_error())
            return self.poll()

        def terminate(self):
            if self.job is not None:
                _check(K.TerminateJobObject(self.job,1))
        kill=terminate

        def active_processes(self):
            accounting=_Accounting()
            _check(K.QueryInformationJobObject(self.job,1,C.byref(accounting),C.sizeof(accounting),None))
            return accounting.active

        def close(self):
            if self.job is not None:
                self.terminate()
                deadline=time.monotonic()+3
                while self.active_processes():
                    if time.monotonic()>=deadline:
                        raise TimeoutError("owned worker descendants have not terminated")
                    time.sleep(.005)
                K.CloseHandle(self.job)
                self.job=None
            if self.process is not None:
                self.wait(timeout=3)
                K.CloseHandle(self.process)
                self.process=None
