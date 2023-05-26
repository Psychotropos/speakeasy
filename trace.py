import os
import logging
import argparse

import speakeasy
import speakeasy.winenv.arch as e_arch


def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('pintool')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.ERROR)

    return logger


class SpeakeasyPintool:

    def __init__(self, target=None, is_sc=False, arch=None, start=None, end=None, logger=None, se_inst=None):
        self.target = target
        self.is_sc = is_sc
        self.arch = arch
        self.logger = logger
        if not se_inst:
            self.se = speakeasy.Speakeasy(logger=self.logger)
        else:
            self.se = se_inst
        self.loaded_modules = []
        self.loaded_shellcode = []
        self.targets = []
        self.breakpoints = {}
        self.start = int(start, 16)
        self.end = int(end, 16)

        self.init_state()
        if self.is_sc and not self.arch:
            raise DebuggerException('Architecture required when tracing shellcode')

        if self.target:
            if not self.is_sc:
                # Load the initial target module
                self.load_module(self.target)
            else:
                self.load_shellcode(self.target, self.arch)

        self.se.emu.timeout = 3600

        if not self.is_sc:
            if len(self.loaded_modules) == 1:
                self.se.run_module(self.loaded_modules[0], all_entrypoints=True)
            else:
                self.se.run_shellcode(self.loaded_shellcode[0], 0)

        self.running = True

    def init_state(self):
        if self.se:
            self.trace_start_reached = False
            self.se.add_code_hook(self.code_hook)
            self.se.add_mem_read_hook(self.mem_read_hook)

    def mem_read_hook(self, emu, access, addr, size, value, ctx):
        if self.trace_start_reached:
            print(f'mr:{addr:#x}:{size}:0x{self.se.mem_read(addr, size).hex().upper()}')

    def code_hook(self, emu, addr, size, ctx):
        '''
        Hook called for each instruction while debugging
        '''
        if addr == self.start:
            self.trace_start_reached = True
        
        if addr == self.end:
            self.se.stop()
            self.running = False
            return

        registers = ('rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')

        if self.trace_start_reached:
            register_values = ':'.join([f'{self.se.reg_read(reg):#x}' for reg in registers])
            print(f'r:{register_values}')
            print(f'i:{addr:#x}:{size}:{self.se.mem_read(addr, size).hex().upper()}')

    def stop(self):
        '''
        Stop running the emulator
        '''
        self.se.stop()
        self.running = False

    def load_module(self, module):
        '''
        Load a module into the emulation space
        '''
        if not os.path.exists(module):
            self.error('Can\'t find module: %s' % (module))
        else:
            module = self.se.load_module(module)
            self.loaded_modules.append(module)

    def load_shellcode(self, sc_path, arch):
        '''
        Load shellcode into the emulation space
        '''

        if self.is_sc:
            arch = arch.lower()
            if arch in ('x86', 'i386'):
                arch = e_arch.ARCH_X86
            elif arch in ('x64', 'amd64'):
                arch = e_arch.ARCH_AMD64
            else:
                raise Exception('Unsupported architecture: %s' % arch)

        if not os.path.exists(sc_path):
            self.error('Can\'t find shellcode: %s' % (sc_path))
        else:
            sc = self.se.load_shellcode(sc_path, arch)
            self.loaded_shellcode.append(sc)
            return sc



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Debug a Windows binary with speakeasy')
    parser.add_argument('-t', '--target', action='store', dest='target',
                        required=True, help='Path to input file to emulate')
    parser.add_argument('-r', '--raw', action='store_true', dest='raw',
                        required=False, help='Attempt to emulate file as-is '
                                             'with no parsing (e.g. shellcode)')
    parser.add_argument('-a', '--arch', action='store', dest='arch',
                        required=False,
                        help='Force architecture to use during emulation (for '
                             'multi-architecture files or shellcode). '
                             'Supported archs: [ x86 | amd64 ]')
    parser.add_argument('-s', '--start', action='store', dest='start', required=True, help='Start address of trace output')
    parser.add_argument('-e', '--end', action='store', dest='end', required=True, help='End address of trace output')

    args = parser.parse_args()

    dbg = SpeakeasyPintool(args.target, args.raw, args.arch, args.start, args.end, logger=get_logger())
