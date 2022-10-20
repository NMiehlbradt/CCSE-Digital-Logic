from enum import Enum


class ParseType(Enum):
    LITERAL = 0,
    VAR = 1


class Instr:

    def __init__(self, name, instr_vars, machine_rep):
        self.name = name
        self.instr_vars = instr_vars
        self.machine_rep = machine_rep

    def emit_machine_code(self, position, labels):
        pass


def parse_instruction_spec(instr_spec, types):
    syntax = instr_spec['asm']
    machine = instr_spec['bin']


def parse_types_spec(spec):

    types = {}
    for name, options in spec:

        def enum_type(string, position, labels):
            if string in options:
                return options[string]
            else:
                raise RuntimeError("Invalid option")

        types[name] = enum_type

    def uint8(string, position, labels):
        num = int(string)
        if True:
            pass  # TODO


def parse_isa_spec(spec):
    types = spec['types']
    instructions = spec['instructions']