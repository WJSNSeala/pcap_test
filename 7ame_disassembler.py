import random
import signal
import sys

PERM_MAPPED             = 0b1000
PERM_READ               = 0b0100
PERM_WRITE              = 0b0010
PERM_EXEC               = 0b0001

TYPE_R = 0
TYPE_I = 1

FLAG_NF = 0b0010
FLAG_ZF = 0b0001

CODE_DEFAULT_BASE   = 0x00000
STACK_DEFAULT_BASE  = 0xf4000


class Register:
    def __init__(self):
        self.register = {}
        self.register_list = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7','r8', 'r9', 'r10', 'bp', 'sp', 'pc', 'eflags', 'zero']

    def init_register(self):
        for reg_name in self.register_list:
            self.register[reg_name] = 0

    def set_register(self, reg, value):
        if isinstance(reg, (int, long)) :
            if reg < len(self.register_list):
                reg = self.register_list[reg]
            else:
                self.terminate("[VM] Invalid register")

        elif reg not in self.register:
            self.terminate("[VM] Invalid register")

        self.register[reg] = value

    def get_register(self, reg):
        if isinstance(reg, (int, long)) :
            if reg < len(self.register_list):
                reg = self.register_list[reg]
            else:
                self.terminate("[VM] Invalid register")

        elif reg not in self.register:
            self.terminate("[VM] Invalid register")

        return self.register[reg]



class Memory:
    def __init__(self, size):
        self.memory = [0 for i in range(size)]
        self.pages = {}
        for page in range(0, size, 0x1000):
            self.pages[page] = 0

    def __getitem__(self, key):
        return self.memory[key]

    def __setitem__(self, key, val):
        self.memory[key] = val

    def get_perm(self, addr):
        if (addr & 0b111111111000000000000) not in self.pages:
            return 0
        else:
            return self.pages[addr & 0b111111111000000000000]

    def set_perm(self, addr, perm):
        self.pages[addr & 0b111111111000000000000] = perm & 0b1111

    def allocate(self, new_perm, addr=None):
        if addr:
            if not (self.get_perm(addr) & PERM_MAPPED):
                self.set_perm(addr, (PERM_MAPPED | new_perm) & 0b1111)
                return addr
            else:
                return -1

        for page, perm in self.pages.items():
            if not (self.get_perm(page) & PERM_MAPPED):
                self.set_perm(page, (PERM_MAPPED | new_perm) & 0b1111)
                return page
        return -1

    def check_permission(self, addr, perm):
        if (self.get_perm(addr) & (PERM_MAPPED | perm)) == (PERM_MAPPED | perm):
            return True
        else:
            return False

class Disassamble:
    def __init__(self):
        self.config     = {'NX':False}
        self.firmware   = None
        self.is_load    = False
        self.register   = Register()
        self.register.init_register()
        self.pipeline   = []
        self.memory     = Memory(2 ** 20)
        self.checkperm  = []
        self.filesystem = FileSystem()

        self.syscall_table  = [self.sys_s0, self.sys_s1,
                               self.sys_s2, self.sys_s3,
                               self.sys_s4, self.sys_s5,
                               self.sys_s6]

        self.op_hander_table = [self.op_x0, self.op_x1,
                                self.op_x2, self.op_x3,
                                self.op_x4, self.op_x5, self.op_x6,
                                self.op_x7, self.op_x8,
                                self.op_x9, self.op_x10,
                                self.op_x11, self.op_x12,
                                self.op_x13, self.op_x14,
                                self.op_x15, self.op_x16,
                                self.op_x17, self.op_x18,
                                self.op_x19, self.op_x20,
                                self.op_x21, self.op_x22,
                                self.op_x23, self.op_x24,
                                self.op_x25, self.op_x26,
                                self.op_x27, self.op_x28,
                                self.op_x29, self.op_x30]
    
    disass_f = open("disas.txt", 'w')

    def load_firmware(self, firm_name):
        try:
            with open(firm_name, 'rb') as f:
                data = f.read()

            self.firmware = [ord(byte) for byte in data]
            self.is_load = True


            if self.config['NX']:
                stack_perm = PERM_READ | PERM_WRITE
            else:
                stack_perm = PERM_READ | PERM_WRITE | PERM_EXEC


            for i in range(0, len(data) / 0x1000 + 1):
                self.memory.allocate(PERM_READ | PERM_WRITE | PERM_EXEC, addr=CODE_DEFAULT_BASE + i*0x1000)

            self.write_memory(CODE_DEFAULT_BASE, self.firmware, len(self.firmware))

            for i in range(0, len(data) / 0x1000 + 1):
                self.memory.set_perm(CODE_DEFAULT_BASE + i*0x1000, PERM_MAPPED | PERM_READ | PERM_EXEC)


            self.memory.allocate(stack_perm, addr=STACK_DEFAULT_BASE)
            self.memory.allocate(stack_perm, addr=STACK_DEFAULT_BASE + 0x1000)

            self.register.set_register('pc', CODE_DEFAULT_BASE)
            self.register.set_register('sp', STACK_DEFAULT_BASE+0x1fe0)

        except:
            self.terminate("[VM] Firmware load error")

    def bit_concat(self, bit_list):
        res = 0
        for bit in bit_list:
            res <<= 7
            res += bit & 0b1111111
        return res

    def execute(self):
        try:
            while 1:
                cur_pc = self.register.get_register('pc')
                op, op_type, opers, op_size = self.dispatch(cur_pc)

                if not self.memory.check_permission(cur_pc, PERM_EXEC) or not self.memory.check_permission(cur_pc + op_size - 1, PERM_EXEC):
                    self.terminate("[VM] Can't exec memory")

                self.register.set_register('pc', cur_pc + op_size)
                op_handler = self.op_hander_table[op]
                op_handler(op_type, opers)
        except:
            self.terminate("[VM] Unknown error")


    def dispatch(self, addr):
        opcode = self.bit_concat(self.read_memory(addr, 2))
        op      = (opcode & 0b11111000000000) >> 9
        if op >= len(self.op_hander_table):
            self.terminate("[VM] Invalid instruction")

        op_type = (opcode & 0b00000100000000) >> 8
        opers   = []
        if op_type == TYPE_R:
            opers.append((opcode & 0b00000011110000) >> 4)
            opers.append((opcode & 0b00000000001111))
            op_size = 2

        elif op_type == TYPE_I:
            opers.append((opcode & 0b00000011110000) >> 4)
            opers.append(self.read_memory_tri(addr+2, 1)[0])
            op_size = 5

        else:
            self.terminate("[VM] Invalid instruction")

        return op, op_type, opers, op_size


    def read_memory(self, addr, length):
        if not length:
            return []

        if self.memory.check_permission(addr, PERM_READ) and self.memory.check_permission(addr + length - 1, PERM_READ):
            res = self.memory[addr : addr + length]
            return res
                                                    
    def read_memory_str(self, addr):
        res = []
        length = 0

        while 0 not in res:
            res.append(self.memory[addr + length])
            length += 1
        res = res[:-1]
        length -= 1

        if not length:
            return '', 0

        if self.memory.check_permission(addr, PERM_READ) and self.memory.check_permission(addr + length - 1, PERM_READ):
            return ''.join(map(chr,res)), length
        else:
            self.terminate("[VM] Can't read memory")


    def read_memory_tri(self, addr, count):
        if not count:
            return []

        if self.memory.check_permission(addr, PERM_READ) and self.memory.check_permission(addr + count*3 - 1, PERM_READ):
            res = []
            for i in range(count):
                tri = 0
                tri |= self.memory[addr + i*3]
                tri |= self.memory[addr + i*3 + 1]  << 14
                tri |= self.memory[addr + i*3 + 2]  << 7
                res.append(tri)
            return res
        else:
            self.terminate("[VM] Can't read memory")


    def write_memory(self, addr, data, length):
        if not length:
            return

        if self.memory.check_permission(addr, PERM_WRITE) and self.memory.check_permission(addr + length - 1, PERM_WRITE):
            for offset in range(length):
                self.memory[addr + offset] = data[offset] & 0b1111111
        else:
            self.terminate("[VM] Can't write memory")


    def write_memory_tri(self,addr,data_list, count):
        if not count:
            return

        if self.memory.check_permission(addr, PERM_WRITE) and self.memory.check_permission(addr + count*3 - 1, PERM_WRITE):
            for i in range(count):
                self.memory[addr + i*3] =       (data_list[i] & 0b000000000000001111111)
                self.memory[addr + i*3 + 1] =   (data_list[i] & 0b111111100000000000000) >> 14
                self.memory[addr + i*3 + 2] =   (data_list[i] & 0b000000011111110000000) >> 7
        else:
            self.terminate("[VM] Can't write memory")


    def op_x0(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1])
            dst = opers[0]

            data = self.read_memory_tri(src, 1)[0]
            self.register.set_register(dst, data)

        else:
            self.terminate("[VM] Invalid instruction")

        result = ""
        result += "READ_TRI "
        result += "[" + opers[1] + "] " 
        result += opers[0] + "\n"
        

    def op_x1(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1])
            dst = opers[0]

            ch = self.read_memory(src, 1)[0]
            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst & 0b111111111111110000000) | ch)
        else:
            self.terminate("[VM] Invalid instruction")
 
        result = ""
        result += "READ_BYTE "
        result += opers[0] + " "
        result += "[" + opers[1] + "]\n" 

    def op_x2(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[0])
            dst = self.register.get_register(opers[1])
            self.write_memory_tri(dst, [src], 1)
        else:
            self.terminate("[VM] Invalid instruction")
        result = ""
        result += "WRITE_TRI "
        result += opers[0] + " "
        result += "[" + opers[1] + "]\n" 

    def op_x3(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[0])
            dst = self.register.get_register(opers[1])
            self.write_memory(dst, [src & 0b1111111], 1)
        else:
            self.terminate("[VM] Invalid instruction")


    def op_x4(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1])
            dst = opers[0]

            self.register.set_register(dst, src)

        elif op_type == TYPE_I:
            src = opers[1]
            dst = opers[0]

            self.register.set_register(dst, src)

        else:
            self.terminate("[VM] Invalid instruction")

    def op_x5(self, op_type, opers):
        if op_type == TYPE_R:
            src = opers[1]
            dst = opers[0]

            org_src = self.register.get_register(src)
            org_dst = self.register.get_register(dst)

            self.register.set_register(src, org_dst)
            self.register.set_register(dst, org_src)

        else:
            self.terminate("[VM] Invalid instruction")


    def op_x6(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[0])
            sp = self.register.get_register('sp')

            self.register.set_register('sp', sp-3)
            self.write_memory_tri(sp-3, [src], 1)

        elif op_type == TYPE_I:
            src = opers[1]
            sp = self.register.get_register('sp')

            self.register.set_register('sp', sp-3)
            self.write_memory_tri(sp-3, [src], 1)

        else:
            self.terminate("[VM] Invalid instruction")


    def op_x7(self, op_type, opers):
        if op_type == TYPE_R:
            dst = opers[0]
            sp = self.register.get_register('sp')

            value = self.read_memory_tri(sp, 1)[0]
            self.register.set_register(dst, value)
            self.register.set_register('sp', sp+3)

        else:
            self.terminate("[VM] Invalid instruction")

    def op_x9(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1])
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst + src) & 0b111111111111111111111)

        elif op_type == TYPE_I:
            src = opers[1]
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst + src) & 0b111111111111111111111)

        else:
            self.terminate("[VM] Invalid instruction")


    def op_x10(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1]) & 0b1111111
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst & 0b111111111111110000000) | ((org_dst + src) & 0b1111111))

        elif op_type == TYPE_I:
            src = opers[1]
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst & 0b111111111111110000000) | ((org_dst + src) & 0b1111111))

        else:
            self.terminate("[VM] Invalid instruction")

    def op_x11(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1])
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst - src) & 0b111111111111111111111)

        elif op_type == TYPE_I:
            src = opers[1]
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst - src) & 0b111111111111111111111)

        else:
            self.terminate("[VM] Invalid instruction")


    def op_x12(self, op_type, opers):
        if op_type == TYPE_R:
            src = self.register.get_register(opers[1]) & 0b1111111
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst & 0b111111111111110000000) | ((org_dst - src) & 0b1111111))

        elif op_type == TYPE_I:
            src = opers[1]
            dst = opers[0]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, (org_dst & 0b111111111111110000000) | ((org_dst - src) & 0b1111111))

        else:
            self.terminate("[VM] Invalid instruction")


    def op_x13(self, op_type, opers):
         if op_type == TYPE_R:
            dst = opers[0]
            value = self.register.get_register(opers[1])

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, org_dst >> value)

         elif op_type == TYPE_I:
            dst = opers[0]
            value = opers[1]

            org_dst = self.register.get_register(dst)
            self.register.set_register(dst, org_dst >> value)
         else:
            self.terminate("[VM] Invalid instruction")




