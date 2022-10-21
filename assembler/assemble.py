import re
from argparse import ArgumentParser


class AssemblerError(Exception):
    def __init__(self, message, line):
        self.message = message
        self.line = line

    def __str__(self):
        return f'[ERROR] {self.message} on line {self.line}'


def parse_reg(reg, line_num):
    reg = reg.lower()
    if reg == 'rz':
        return '000'
    if reg == 'sp':
        return '110'
    if reg == 'lr':
        return '111'
    m = re.search('^r([0-7)])$', reg)
    if m is not None:
        return f'{int(m.groups()[0]):03b}'
    else:
        raise AssemblerError(f'Invalid register \'{reg}\'', line_num)


def parse_mem(block, line_num):
    if block[0] != '[' or block[-1] != ']':
        raise AssemblerError(f'Expect brackets around argument \'{block}\'', line_num)
    return parse_reg(block[1:-1].strip(), line_num)


def parse_number(bits, signed):
    def parse(num_string, line_num):
        num_string = num_string.lower()
        try:
            if '0x' in num_string:
                base = 16
            elif '0b' in num_string:
                base = 2
            elif '0o' in num_string:
                base = 8
            else:
                base = 10
            num = int(num_string, base=base)
        except ValueError:
            raise AssemblerError(f'Invalid number \'{num_string}\'', line_num)

        return format_number(num, bits, signed, line_num)

    return parse


def format_number(num, bits, signed, line_num):
    lb = -1 << bits - 1 if signed else 0
    ub = 1 << bits - 1 if signed else 1 << bits

    if num < lb or num >= ub:
        raise AssemblerError(f'Number {num} is out of range ({lb} - {ub})', line_num)

    return format((1 << bits) + num if num < 0 else num, f'0{bits}b')


def parse_label_or_num(bits, signed):
    def parse(string, line_num):
        try:
            return True, parse_number(bits, signed)(string, line_num)
        except AssemblerError:
            return False, string

    return parse


def label_to_num(labels, is_num, target, bits, signed, line_num, address=0):
    if not is_num:
        if target in labels:
            target = format_number(labels[target] - address, bits, signed, line_num)
        else:
            raise AssemblerError(f'Label \'{target}\' not defined', line_num)
    return target


def parse_args(instr, args, parser_map, line_num):
    if len(args) != len(parser_map):
        raise AssemblerError(f'Incorrect number of arguments for instruction \'{instr}\'. '
                             f'Expected {len(parser_map)}, got {len(args)}', line_num)

    return {name: parser(arg, line_num) for arg, (name, parser) in zip(args, parser_map)}


def mk_instr(*bin_rep):
    return [lambda _: b for b in bin_rep]


def i_instr(op, rd, imm8):
    return mk_instr(f'{op:04b}0{rd}{imm8}')


def r_instr(op, rd, ra, rb):
    return mk_instr(f'{op:04b}0{rd}0{ra}0{rb}')


def l_instr(op, imm12):
    return mk_instr(f'{op:04b}{imm12}')


def parse_line(line, line_num, address):
    line = line.split('#', 1)[0].strip().split(':', 1)
    if len(line) == 2:
        label = line[0].strip()
        rest = line[1].strip()
    else:
        label = None
        rest = line[0].strip()

    if label is not None and not label[0].isalpha():
        raise AssemblerError(f'Invalid label \'{label}\', labels must begin with an alphabetic character', line_num)

    if rest == '':
        return label, []

    # Parse instruction
    op, *rest = map(str.strip, rest.split(' ', 1))
    if len(rest) < 1:
        args = ''
    else:
        args = list(map(str.strip, rest[0].split(',')))

    op = op.lower()

    if op[0] == '.':
        # Parse assembler directive
        op = op[1:]
        if op == 'long':
            def parse_arg(arg):
                is_signed = arg[0] == '-'
                parsed = parse_label_or_num(16, is_signed)(arg, line_num)
                return lambda l: label_to_num(l, *parsed, 16, is_signed, line_num)

            binary = [parse_arg(arg) for arg in args]
        else:
            raise AssemblerError(f'Unknown assembler directive \'{op}\'', line_num)
    else:
        # Parse instruction
        if op == 'put':
            params = parse_args(op, args, [('rd', parse_reg), ('imm8', parse_label_or_num(8, False))], line_num)

            def mk_put(labels):
                target = label_to_num(labels, *params['imm8'], 8, False, line_num)
                return i_instr(0, params['rd'], target)[0](labels)

            binary = [mk_put]
        elif op[0] == 'j':
            params = parse_args(op, args, [('target', parse_label_or_num(8, True))], line_num)
            jmp_type = op[1:]
            if jmp_type == 'nz':
                jmp_code = '0000'
            elif jmp_type == 'z':
                jmp_code = '0001'
            elif jmp_type == '' or jmp_type == 'al':
                jmp_code = '1111'
            else:
                raise AssemblerError(f'Unknown jump type \'{jmp_type}\'', line_num)

            def mk_jmp_instr(labels):
                target = label_to_num(labels, *params['target'], 8, True, line_num, address=address)
                return f'0010{jmp_code}{target}'

            binary = [mk_jmp_instr]
            pass
        elif op == 'call':
            params = parse_args(op, args, [('imm12', parse_label_or_num(12, True))], line_num)

            def mk_call(labels):
                target = label_to_num(labels, *params['imm12'], 12, True, line_num, address=address)
                if int(target) == 0:
                    raise AssemblerError('Call instruction cannot have an offset of 0', line_num)
                return l_instr(3, target)[0](labels)

            binary = [mk_call]
        elif op == 'ret':
            params = parse_args(op, args, [], line_num)
            binary = l_instr(3, format_number(0, 12, False, line_num))
        elif op == 'ldr':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_mem)], line_num)
            binary = r_instr(4, params['rd'], params['ra'], '000')
        elif op == 'str':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_mem)], line_num)
            binary = r_instr(5, params['rd'], params['ra'], '000')
        elif op == 'add':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_reg), ('rb', parse_reg)], line_num)
            binary = r_instr(8, params['rd'], params['ra'], params['rb'])
        elif op == 'orr':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_reg), ('rb', parse_reg)], line_num)
            binary = r_instr(9, params['rd'], params['ra'], params['rb'])
        elif op == 'and':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_reg), ('rb', parse_reg)], line_num)
            binary = r_instr(10, params['rd'], params['ra'], params['rb'])
        elif op == 'not':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_reg)], line_num)
            binary = r_instr(11, params['rd'], params['ra'], '000')
        elif op == 'sub':
            params = parse_args(op, args, [('rd', parse_reg), ('ra', parse_reg), ('rb', parse_reg)], line_num)
            binary = r_instr(12, params['rd'], params['ra'], params['rb'])
        # Pseudo ops
        elif op == 'nop':
            params = parse_args(0, args, [], line_num)
            binary = mk_instr('0000000000000000')
        elif op == 'cmp':
            params = parse_args(op, args, [('ra', parse_reg), ('rb', parse_reg)], line_num)
            binary = r_instr(12, '000', params['ra'], params['rb'])
        elif op == 'mov':
            params = parse_args(op, args, [('rd', parse_reg), ('rs', parse_reg)], line_num)
            binary = r_instr(8, params['rd'], params['rs'], '000')
        else:
            raise AssemblerError(f'Invalid opcode \'{op}\'', line_num)

    return label, binary


def parse_lines(lines):
    current_address = 0
    labels = {}
    contents = []
    errors = 0
    for line_num, line in enumerate(lines):
        try:
            label, binary = parse_line(line, line_num+1, current_address)
            if label is not None:
                if label in labels:
                    raise AssemblerError(f'Redefined label \'{label}\'', line_num)
                labels[label] = current_address
            contents += binary
            current_address += len(binary)
        except AssemblerError as asm_err:
            print(asm_err)
            errors += 1

    machine_code = []

    for gen in contents:
        try:
            b = gen(labels)
            machine_code.append(int(b, base=2))
        except AssemblerError as asm_err:
            print(asm_err)
            errors += 1

    return errors, machine_code, labels


if __name__ == '__main__':
    parser = ArgumentParser()

    parser.add_argument('asm', help='the assembly file to assemble')
    parser.add_argument('--out', '-o', help='write binary output to this file')
    parser.add_argument('--show', '-s', action='store_true', help='print assembled binary in hexadecimal')
    parser.add_argument('--labels', '-l', action='store_true', help='show the labels and their addresses')

    args = parser.parse_args()

    with open(args.asm) as f:
        assembly_code = f.readlines()

    errors, machine_code, labels = parse_lines(assembly_code)
    if errors > 0:
        print(f'Assembly failed, {errors} error{"s" if errors > 1 else ""}')
        exit(1)

    if args.labels:
        print('Labels:')
        print(labels)
        print('-'*80)
    if args.show or args.out is None:
        print('\n'.join(f'0x{addr:04x}: 0x{instr:04x} ' for addr, instr in enumerate(machine_code)))

    if args.out is not None:
        with open(args.out, 'wb') as f:
            f.writelines(int.to_bytes(instr, 2, 'little') for instr in machine_code)


