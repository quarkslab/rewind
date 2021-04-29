
import os
import json

import click
import pykd


class System(object):

    TSC = 0x10
    APIC_BASE = 0x1b

    IA32_SYSENTER_CS = 0x174
    IA32_SYSENTER_ESP = 0x175
    IA32_SYSENTER_EIP = 0x176

    PAT = 0x277

    IA32_EFER = 0xC0000080
    STAR = 0xC0000081
    LSTAR = 0xC0000082
    CSTAR = 0xC0000083
    SFMASK = 0xC0000084

    FS_BASE = 0xC0000100
    GS_BASE = 0xC0000101
    KERNEL_GS_BASE = 0xC0000102

    TSC_AUX = 0xC00000103

    def __init__(self):
        pykd.setSymbolPath(r"srv*c:\symbols*https://msdl.microsoft.com/download/symbols")

    def get_reg(self, name):
        return pykd.reg(name)

    def read_virtual_address(self, address, size):
        return bytes(pykd.loadBytes(address, size))

    def read_physical_address(self, address, size):
        return bytes(pykd.loadBytes(address, size, True))

    def read_qword(self, address):
        return pykd.ptrQWord(address)

    def get_symbol(self, address):
        return pykd.findSymbolAndDisp(address)

    def get_formatted_symbol(self, address):
        try:
            symbol = self.get_symbol(address)
            return F"{symbol[0]}!{symbol[1]}+0x{symbol[2]:x}"
        except Exception:
            return None

    def get_address(self, name):
        return pykd.getOffset(name)

    def read_msr(self, msr):
        return pykd.rdmsr(msr)

    def get_module(self, address):
        return pykd.module(address)

    def expr(self, expr):
        return pykd.expr(expr)

    def get_segment(self, segment):
        selector = self.get_reg(segment)
        output = pykd.dbgCommand("dg %x" % (selector))
        line = output.splitlines()[-1]
        tokens = line.split()
        segment = {}
        segment["selector"] = pykd.expr(tokens[0])
        segment["base"] = pykd.expr(tokens[1])
        segment["limit"] = pykd.expr(tokens[2])
        segment["flags"] = pykd.expr(tokens[11])
        return segment


@click.command()
@click.argument("path")
@click.option("--overwrite", is_flag=True)
@click.option("--full", is_flag=True)
def cli(path, overwrite, full):
    system = System()

    address = system.get_address("nt!NtBuildLabEx")
    build = pykd.loadCStr(address)

    module, name, offset = system.get_symbol(system.get_reg("rip"))
    if offset != 0:
        print("error: not on function boundary")
        return

    path = os.path.join(path, build, module, name)

    if not overwrite and os.path.exists(path):
        print("error: target path already present")
        return

    os.makedirs(path, exist_ok=True)

    context = {}
    context["gdtr"] = system.get_reg("gdtr")
    context["gdtl"] = system.get_reg("gdtl")

    context["idtr"] = system.get_reg("idtr")
    context["idtl"] = system.get_reg("idtl")

    context["cr0"] = system.get_reg("cr0")
    context["cr3"] = system.get_reg("cr3")
    context["cr4"] = system.get_reg("cr4")
    context["cr8"] = system.get_reg("cr8")
    context["efer"] = system.read_msr(system.IA32_EFER)

    context["cs"] = system.get_segment("cs")
    # FIXME: flags are wrong
    context["cs"]["flags"] |= 0x2000

    context["ss"] = system.get_segment("ss")
    context["ds"] = system.get_segment("ds")
    context["es"] = system.get_segment("es")

    context["fs"] = system.get_segment("fs")
    context["gs"] = system.get_segment("gs")

    context["fs_base"] = system.read_msr(system.FS_BASE)
    context["gs_base"] = system.read_msr(system.GS_BASE)
    context["kernel_gs_base"] = system.read_msr(system.KERNEL_GS_BASE)

    context["sysenter_cs"] = system.read_msr(system.IA32_SYSENTER_CS)
    context["sysenter_esp"] = system.read_msr(system.IA32_SYSENTER_ESP)
    context["sysenter_eip"] = system.read_msr(system.IA32_SYSENTER_EIP)

    context["star"] = system.read_msr(system.STAR)
    context["lstar"] = system.read_msr(system.LSTAR)
    context["cstar"] = system.read_msr(system.CSTAR)

    context["apic_base"] = system.read_msr(system.APIC_BASE)

    context["rax"] = system.get_reg("rax")
    context["rbx"] = system.get_reg("rbx")
    context["rcx"] = system.get_reg("rcx")
    context["rdx"] = system.get_reg("rdx")
    context["rsi"] = system.get_reg("rsi")
    context["rdi"] = system.get_reg("rdi")
    context["r8"] = system.get_reg("r8")
    context["r9"] = system.get_reg("r9")
    context["r10"] = system.get_reg("r10")
    context["r11"] = system.get_reg("r11")
    context["r12"] = system.get_reg("r12")
    context["r13"] = system.get_reg("r13")
    context["r14"] = system.get_reg("r14")
    context["r15"] = system.get_reg("r15")

    context["rbp"] = system.get_reg("rbp")
    context["rsp"] = system.get_reg("rsp")

    context["rip"] = system.get_reg("rip")
    context["rflags"] = system.get_reg("efl")

    print("saving context")
    with open(os.path.join(path, "context.json"), "w") as fp:
        json.dump(context, fp, indent=2)

    params = {}
    params["return_address"] = system.read_qword(system.get_reg("rsp"))
    params["excluded_addresses"] = {}
    params["excluded_addresses"]["nt!KeBugCheck"] = system.get_address("nt!KeBugCheck")
    params["excluded_addresses"]["nt!KeBugCheck2"] = system.get_address("nt!KeBugCheck2")
    params["excluded_addresses"]["nt!KeBugCheckEx"] = system.get_address("nt!KeBugCheckEx")

    print("saving parameters")
    with open(os.path.join(path, "params.json"), "w") as fp:
        json.dump(params, fp, indent=2)

    print("saving memory")
    if not full:
        pykd.dbgCommand(".dump /ka /o %s" % (os.path.join(path, "mem.dmp")))
    else:
        pykd.dbgCommand(".dump /f /o %s" % (os.path.join(path, "mem.dmp")))

    print("done")


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
