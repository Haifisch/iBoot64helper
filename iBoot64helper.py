# argp@census-labs.com

import idc
import idaapi
import ida_auto
import ida_search
import idautils
import ida_search
import ida_funcs
import ida_segment
import ida_name
import ida_bytes
import ida_funcs
import struct

true = True
false = False
none = None

prologues = ["BD A9", "BF A9", "7F 23 03 D5"]

def find_panic(base_ea):
    pk_ea = ida_search.find_text(base_ea, 1, 1, "double panic in ", ida_search.SEARCH_NEXT)
    if pk_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(pk_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _panic = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_panic")
            return func.start_ea

    return idaapi.BADADDR

def find_image4_load(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x4D650000)

    if ea_list[0] != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _image4_load = 0x%x" % (func_ea))
        ida_name.set_name(func_ea, "_image4_load")
        return func_ea

    return idaapi.BADADDR

def find_img4decodeinit(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0x494D0000)

    if ea_list[0] != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        ea_func_list = list(idautils.XrefsTo(func_ea))

        if ea_func_list[0].frm != idaapi.BADADDR:
            i4d_ea = ida_funcs.get_func(ea_func_list[0].frm).start_ea
            print("\t[+] _Img4DecodeInit = 0x%x" % (i4d_ea))
            ida_name.set_name(i4d_ea, "_Img4DecodeInit")
            return i4d_ea

    return idaapi.BADADDR

def find_aes_crypto_cmd(base_ea):
    aes_ea = ida_search.find_text(base_ea, 1, 1, "aes_crypto_cmd", ida_search.SEARCH_NEXT)

    if aes_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(aes_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _aes_crypto_cmd = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_aes_crypto_cmd")
            return func.start_ea

    return idaapi.BADADDR

def find_update_device_tree(base_ea):
    udt_ea = ida_search.find_text(base_ea, 1, 1, "development-cert", ida_search.SEARCH_NEXT)

    if udt_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(udt_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _UpdateDeviceTree = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_UpdateDeviceTree")
            return func.start_ea

    return idaapi.BADADDR

def find_macho_valid(base_ea):
    ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFACF)

    if ea_list[0] == idaapi.BADADDR:
        ea_list = ida_search.find_imm(base_ea, ida_search.SEARCH_DOWN, 0xFEEDFACF)
    
    if ea_list[0] != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0]).start_ea
        print("\t[+] _macho_valid = 0x%x" % (func_ea))
        ida_name.set_name(func_ea, "_macho_valid")
        return func_ea

    return idaapi.BADADDR

def find_loaded_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _loaded_kernelcache = 0x%x" % (func_ea))
        ida_name.set_name(func_ea, "_loaded_kernelcache")
        return func_ea

    return idaapi.BADADDR

def find_load_kernelcache(ea):
    ea_list = list(idautils.XrefsTo(ea))

    if ea_list[0].frm != idaapi.BADADDR:
        func_ea = ida_funcs.get_func(ea_list[0].frm).start_ea
        print("\t[+] _load_kernelcache = 0x%x" % (func_ea))
        ida_name.set_name(func_ea, "_load_kernelcache")
        return func_ea

    return idaapi.BADADDR

def find_do_go(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Memory image not valid", ida_search.SEARCH_NEXT)

    if str_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _do_go = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_do_go")
            return func.start_ea

    return idaapi.BADADDR

def find_pmgr_binning_mode_get_value(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "Invalid low", ida_search.SEARCH_NEXT)

    if str_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _pmgr_binning_mode_get_value = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_pmgr_binning_mode_get_value")
            return func.start_ea

    return idaapi.BADADDR

def find_do_printf(base_ea):
    str_ea = ida_search.find_text(base_ea, 1, 1, "<ptr>", ida_search.SEARCH_NEXT)

    if str_ea != idaapi.BADADDR:
        for xref in idautils.XrefsTo(str_ea):
            func = ida_funcs.get_func(xref.frm)
            print("\t[+] _do_printf = 0x%x" % (func.start_ea))
            ida_name.set_name(func.start_ea, "_do_printf")
            return func.start_ea

    return idaapi.BADADDR

def find_putchar(base_ea):
    str_ea = ida_name.get_name_ea(idaapi.BADADDR, "aPanic")

    if str_ea != idaapi.BADADDR:
        apanic_ea = list(idautils.XrefsTo(str_ea))[0].frm

        if apanic_ea == idaapi.BADADDR:
            return idaapi.BADADDR

        opnd0 = idc.print_operand(apanic_ea + 8, 0)
        ins_str = idaapi.ua_mnem(apanic_ea + 8)

        if ins_str == "BL":
            func_ea = ida_name.get_name_ea(idaapi.BADADDR,opnd0)
            ea = func_ea

            while ea != idaapi.BADADDR:
                ins_str = idaapi.ua_mnem(ea)
                
                if ins_str == "ADD":
                    opnd2 = idc.print_operand(ea, 2)
                    
                    if opnd2 == "#1":
                        ins_ea = ea - 4
                        opnd0 = idc.print_operand(ins_ea, 0)
                        ins_str = idaapi.ua_mnem(ins_ea)

                        if ins_str == "BL":
                            pc_ea = ida_name.get_name_ea(idaapi.BADADDR,opnd0)
                            print("\t[+] _putchar = 0x%x" % (pc_ea))
                            ida_name.set_name(pc_ea, "_putchar")
                            return pc_ea

                ea = ea + 4

    return idaapi.BADADDR

def find_macho_load(base_ea):
    pz_ea = ida_name.get_name_ea(idaapi.BADADDR,"aPagezero")

    if pz_ea != idaapi.BADADDR:
        if len(list(idautils.XrefsTo(pz_ea))) != 3:
            return idaapi.BADADDR

        func1_ea = ida_funcs.get_func(list(idautils.XrefsTo(pz_ea))[0].frm).start_ea
        func2_ea = ida_funcs.get_func(list(idautils.XrefsTo(pz_ea))[1].frm).start_ea
        func3_ea = ida_funcs.get_func(list(idautils.XrefsTo(pz_ea))[2].frm).start_ea

        if func2_ea != func3_ea:
            return idaapi.BADADDR

        if func1_ea != func2_ea:
            print("\t[+] _macho_load = 0x%x" % (func2_ea))
            ida_name.set_name(func2_ea, "_macho_load")
            return func2_ea

    return idaapi.BADADDR

def find_interesting(base_ea):
    mv_ea = find_macho_valid(base_ea)
    if mv_ea != idaapi.BADADDR:
        ldk_ea = find_loaded_kernelcache(mv_ea)
        lk_ea = find_load_kernelcache(ldk_ea)
    
    pk_ea = find_panic(base_ea)
    go_ea = find_do_go(base_ea)
    pr_ea = find_do_printf(base_ea)
    i4l_ea = find_image4_load(base_ea)
    i4d_ea = find_img4decodeinit(base_ea)
    aes_ea = find_aes_crypto_cmd(base_ea)
    udt_ea = find_update_device_tree(base_ea)
    ml_ea = find_macho_load(base_ea)
    pgv_ea = find_pmgr_binning_mode_get_value(base_ea)

    pc_ea = find_putchar(base_ea)
    if pc_ea != idaapi.BADADDR and mv_ea == idaapi.BADADDR:
        # this is a SecureROM image
        segm = ida_segment.getseg(base_ea)
        if segm:
            idaapi.set_segm_name(segm, "SecureROM", 0)
            print("[+] Identified as a SecureROM image")

def accept_file(fd, fname):
    print("accept_file => "+str(format))
    version = 0
    ret = 0
    if type(fname) == str:
        fd.seek(0x280)
        ver_str = fd.read(0x20)
        print(ver_str)
        if ver_str[:5].decode() == "iBoot":
            version = ver_str[6:] # for later
            print(version)
            ret = {"format" : "iBoot (AArch64)", "processor" : "arm"}
    return ret

def load_file(fd, neflags, format):
    global prologues
    size = 0
    base_addr = 0
    ea = 0
    nfunc = 0
    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER)
    idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT
    if (neflags & idaapi.NEF_RELOAD) != 0:
        return 1
    fd.seek(0, idaapi.SEEK_END)
    size = fd.tell()
    segm = idaapi.segment_t()
    segm.bitness = 2 # 64-bit
    segm.start_ea = 0
    segm.end_ea = size
    idaapi.add_segm_ex(segm, "iBoot", "CODE", idaapi.ADDSEG_OR_DIE)
    fd.seek(0)
    fd.file2base(0, 0, size, False)
    idaapi.add_entry(0, 0, "start", 1)
    idaapi.add_func(ea, idaapi.BADADDR)
    print("[+] Marked as code")
    # heuristic
    while(True):
        mnemonic = idaapi.ua_mnem(ea)
        if mnemonic == None:
            mnemonic = ''
        if "LDR" in mnemonic:
            base_str = idc.print_operand(ea, 1)
            base_addr = int(base_str.split("=")[1], 16)
            break
        ea += 4
    print("[+] Rebasing to address 0x%x" % (base_addr))
    idaapi.rebase_program(base_addr, idc.MSF_NOFIX)
    ida_auto.auto_wait()

    segment_start = base_addr
    segment_end = idc.get_segm_attr(segment_start, idc.SEGATTR_END)
    ea = segment_start

    print("[+] Searching and defining functions")

    for prologue in prologues:
        while ea != idc.BADADDR:
            ea = idc.find_binary(ea, idc.ida_search.SEARCH_DOWN, prologue, 16)
            if ea != idc.BADADDR:
                ea = ea - 2
                if (ea % 4) == 0 and ida_bytes.get_flags(ea) < 0x200:
                    print("[+] Defining a function at 0x%x" % (ea))
                    idaapi.add_func(ea, idaapi.BADADDR)
                    nfunc = nfunc + 1
                ea = ea + 4
    
    ida_auto.plan_and_wait(segment_start, segment_end)
    print("[+] Identified %d new functions" % (nfunc))
    print("[+] Looking for interesting functions")
    find_interesting(segment_start)
    return 1

# EOF