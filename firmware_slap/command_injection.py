import angr
import string
import claripy
import IPython


class SystemLibc(angr.procedures.libc.system.system):
    def check_exploitable(self, cmd):

        # cmd is a pointer to a string
        value = self.state.memory.load(cmd)

        # We can't interact with raw bitvectors as potential system candidates
        if 'claripy.ast.bv.BV' in str(type(cmd)):
            return False
        clarip = cmd.to_claripy()
        location = self.state.solver.eval(clarip)
        value_length = int("0x" + str(value.length), 16)
        symbolic_list = [self.state.memory.load(self.state.se.eval(clarip, cast_to=int) + x).get_byte(0).symbolic for x in range(value_length)]

        position = 0
        count = 0
        greatest_count = 0
        prev_item = symbolic_list[0]
        for i in range(1, len(symbolic_list)):
            if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
                count = count + 1
                if (count > greatest_count):
                    greatest_count = count
                    position = i - count
            else:
                if (count > greatest_count):
                    greatest_count = count
                    position = i - 1 - count
                    # previous position minus greatest count
                count = 0

        if greatest_count >= len("`reboot`"):
            val_loc = self.state.memory.load(location + position, len("`reboot`"))
            if self.state.satisfiable(extra_constraints=[val_loc=="`reboot`"]):
                self.state.add_constraints(val_loc == "`reboot`")

                self.state.globals['exploitable'] = True
                self.state.globals['commandInjection'] = True
                self.state.globals['cmd'] = "`reboot`"
                self.state.globals['val_addr'] = location
                self.state.globals['val_offset'] = location + position
#                self.state.globals['val_str'] = val_str
        elif greatest_count >= len("`ls`"):
            val_loc = self.state.memory.load(location + position, len("`ls`"))
            if self.state.satisfiable(extra_constraints=[val_loc=="`ls`"]):
                self.state.add_constraints(val_loc == "`ls`")

                self.state.globals['exploitable'] = True
                self.state.globals['commandInjection'] = True
                self.state.globals['cmd'] = "`ls`"
                self.state.globals['val_addr'] = location
                self.state.globals['val_offset'] = location + position
#                self.state.globals['val_str'] = val_str

    def check_for_constraint(self):
        actions = [x for x in self.state.history.actions]
        for action in actions:
            if type(action) == angr.state_plugins.sim_action.SimActionData and action.actual_value is not None:
                value_str = self.state.se.eval(action.actual_value, cast_to=bytes).decode('utf-8', 'ignore')
                value_print_str = ''.join((c if c in string.printable else '' for c in value_str))
                value_hex = hex(self.state.se.eval(action.actual_value))
                value_address = str(action.actual_addrs).replace("[", "").replace("]", "").replace("L", "")
                value_address = int(value_address)
                if "`ls`" in value_str or "`reboot`" in value_str:
                    return (True, value_str, value_address)
        for x,y,z in self.state.globals['args']:
            value_str = self.state.se.eval(z , cast_to=bytes).decode('utf-8', 'ignore')
            value_print_str = ''.join((c if c in string.printable else '' for c in value_str))
            value_hex = hex(self.state.se.eval(z))
            value_address = str(action.actual_addrs).replace("[", "").replace("]", "").replace("L", "")
            value_address = int(value_address)
            if "`ls`" in value_str or "`reboot`" in value_str:
                return (True, value_str, value_address)


        return (False, None, None)

    def constrain_control(self, state, symbolic_variable, start_loc, select_string="`ls`"):
        for i in range(len(select_string)):
            current_byte = state.memory.load(start_loc + i).get_byte(0)
            state.add_constraints(claripy.Or(claripy.And(select_string[i] == current_byte)))

    def run(self, cmd):
        self.check_exploitable(cmd)
        return super(type(self), self).run(cmd)

