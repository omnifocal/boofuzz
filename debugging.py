import cPickle
import pprint
import sys
import zlib

import distorm3

currentOS = sys.platform

def disasm_around(trace, starting_addr, size, arch='64'):
    '''
    returns the disassembly starting at addr for size instructions.

    @type  trace: vtrace
    @param trace: instance of vtrace
    @type  addr: int
    @param addr: address where to begin disassembly
    @type  size: int
    @param size: number of instructions to disassemble
    '''
    disasm = []
    try:
        code = trace.readMemory(starting_addr, size)
    except:
        raise Exception("unable to read memory for disasm")

    if arch == '32':
        asm_arch = distorm3.Decode32Bits
    elif arch == '64':
        asm_arch = distorm3.Decode64Bits
    elif arch == '16':
        asm_arch = distorm3.Decode16Bits

    for inst in distorm3.DecomposeGenerator(starting_addr,
                                            code,
                                            asm_arch):
        if not inst.valid:
            return disasm
        else:
            disasm.append(inst)
    return disasm

def dump_register_context(regs, print_dots=False):
    """
    grab the values for each register

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  print_dots: boolean
    @param print_dots: print dots for non-ascii characters

    @rtype:  string
    @return: ascii string representation of register contexts
    """
    register_string = ""

    for i in sorted(regs.keys()):
        ascii_view = ""
        bytes_view = []
        for byte in str(regs[i]):
            if ord(byte) >= 0x20 and ord(byte) < 0x7f:
                ascii_view += byte
            else:
                if print_dots:
                    ascii_view += '.'
            bytes_view.append("\\x%02x" % ord(byte))
        register_string += '%s: %s-> %s\n' % (i, ''.join(bytes_view), ascii_view, )
    return register_string

def register_context(trace, thread=None):
    """
    grab the values for each register

    @type  trace: vtrace
    @param trace: Instance of vtrace

    @rtype:  dict
    @return: register contexts
    """
    registers = {}
    count = 0

    if not(thread):
        regs = trace
    else:
        regs = trace.getRegisterContext(threadid=thread)

    for reg in regs.getRegisterNames():
        registers[reg] = regs.getRegisterByName(reg)
    return registers

def stack_unwind(trace, thread=None):
    '''
    walk and save the stack trace for the current (or specified) thread.
    will be saved in the format [rva, instr addr, frame pointer]

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  thread: integer
    @param thread: id of thread to process seh chain

    @rtype:  list
    @return: list containing stack trace in (rva, instr addr, frame pointer) format
    '''
    call_chain = trace.getStackTrace()

    for i in xrange(len(call_chain)):
        addr  = call_chain[i][0]
        frame = call_chain[i][1]
        try:
            rva = addr_to_rva(trace, addr)
        except:
            rva = ''
        call_chain[i] = "rva: %20s\t addr: 0x%08x\t frame:0x%08x" \
                        % (rva, addr, frame)

    return call_chain

def addr_to_rva(trace, addr):
    """
    Convert a virtual address to the RVA with a module name so we
    can find it even with ASLR.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  addr: integer
    @param addr: address to convert to relative virtual address (rva)

    @rtype:  string
    @return: string representation of rva in [module base]+offset format
    """
    sym_for_addr = ''
    if trace.getSymByAddr(addr , False):
        sym_for_ret_addr = '[ ' + trace.getSymByAddr(addr, False) + ']'

    mem_map = trace.getMemoryMap(addr)

    if not(mem_map):
        raise Exception("memory not mapped")

    rva = addr - mem_map[0]
    base_module = mem_map[3][mem_map[3].rfind('\\'):].replace('\\','')
    base_module = base_module.replace('.dll','')

    return base_module + ('+%08x' % rva) + ' ' + sym_for_addr
