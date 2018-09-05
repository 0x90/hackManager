import winappdbg
import inspect
import os

__websites__ = [
    "https://www.github.com/SirFroweey/",
    "https://pypi.python.org/pypi/hackManager",
    "https://www.github.com/SirFroweey/hackManager"
]
__info__ = "Memory hacking software"
__author__ = "SirFroweey (a.k.a Froweey)"
__version__ = "2.5.2"
__date__ = "09/06/2018"


# This project was created using winappdbg.
# Check out http://winappdbg.sourceforge.net/doc/latest/tutorial/ for more details.


class BasicEventHandler(winappdbg.EventHandler):
    """EventHandler for our winappdbg debugger."""

    def __init__(self, hook_dict):
        winappdbg.EventHandler.__init__(self)
        self.hooks = hook_dict

    def load_dll(self, event):
        pid = event.get_pid()
        module = event.get_module()
        for dict_module_name in list(self.hooks.keys()):
            if isinstance(dict_module_name, int):
                # Internal function hooks.
                dict_module_function, signatures = self.hooks.get(dict_module_name)[0]
                event.debug.hook_function(pid, dict_module_name, dict_module_function, signature=signatures)
            else:
                # External DLL function hooks.
                values = self.hooks.get(dict_module_name)
                for entry in values:
                    dict_module_function_name, dict_module_function = entry
                    if module.match_name(dict_module_name):
                        event.debug.hook_function(
                            pid,
                            module.resolve(dict_module_function_name),
                            dict_module_function,
                            paramCount=len(inspect.getargspec(dict_module_function)[0]) - 2
                        )


class Hack(object):
    """Base class utilized to make hack development for any type of game/software easy."""

    def __init__(self, name=None, pid=None):
        """
        process_name = 'Notepad'
        i = Hack(process_name).
        # If no process is supplied, then you do:
        i = Hack().find_process()
        print i.running
        # to get a list the currently running processes.

        :processName: (string) exact process name.
        :pid: (int) process id.
        """

        self.module_base_dict = {}
        self.name = name
        self.pid = None
        self.threads = {}
        self.process = None
        self.debug = None
        self.hook_dict = {}
        self.base_address = None
        self.last_address = None
        self.running = []
        self.find_process(name, pid)
        if self.process is not None:
            self.get_base_address()

    def __repr__(self):
        return "<Hack instance: %s pid: %i>" % (str(self.name), self.pid)

    def set_last_address(self):
        self.last_address = self.module_base_dict.get(
            self.module_base_dict.keys()[::-1][0]
        )

    def add_hook(self, module_name, function_name, function_handle):
        """
        Add hook to an external DLL function.
        :param module_name: (string) module name (i.e: 'ws2_32.dll')
        :param function_name: (string) function name (i.e: 'send')
        :param function_handle: (string) function event callback (i.e.: 'mycallback')
        """
        key = self.hook_dict.get(module_name)
        if key is not None:
            key.append((function_name, function_handle))
        else:
            self.hook_dict[module_name] = [(function_name, function_handle)]

    def add_internal_hook(self, address, function_handle, signature=()):
        """
        Add hook to an internal function.
        :param address: (int/hex) Memory address of internal functin.
        :param function_handle: callback function.
        :param signature: byte-code signature used to find function.
        """
        self.hook_dict[address] = [(function_handle, signature)]

    def hook(self):
        """
        Hook onto one or more of the processes module functions. 

        Example code: 
        hook_dict = {'ws2_32.dll': ['send', 'sendto']}
        Hack('process_name.exe').hook(hook_dict)
        """
        if self.process is None:
            raise ValueError("You need to specify the process name, i.e.: Hack('process_name.exe').hook()")

        if len(self.hook_dict.keys()) == 0:
            raise ValueError("You need to call Hack().add_hook() first! You currently haven't added any hooks!")
        self.debug = winappdbg.Debug(BasicEventHandler(self.hook_dict))
        try:
            self.debug.attach(self.process.get_pid())
            self.debug.loop()
        finally:
            self.debug.stop()

    def get_threads(self):
        """
        Get running thread list.
        You can call .suspend(), .resume(), .kill(), .name(), \
        .set_name(), .is_hidden(), .set_process(), etc.
        Check out http://winappdbg.sourceforge.net/doc/v1.4/reference/winappdbg.system.Thread-class.html for more info.
        """
        process = self.process
        for thread in process.iter_threads():
            self.threads[str(thread.get_tid())] = thread

    @classmethod
    def change_window_title(cls, title, new_title):
        """
        Change the specified window's title to the new_title. \
        (title, new_title).

        This is a class-method.

        i.e.: Hack.change_window_title('Cheat Engine 6.1', 'Undetected CE')
        """
        try:
            _window = winappdbg.System.find_window(windowName=title)
        except:
            _window = None

        if _window:
            _window.set_text(new_title)
            return _window

        return False

    def find_process(self, name=None, pid=None):
        """
        If a processName is not passed, then it will return the list of running processes.
        Do NOT call this method(function) directly. It is called by the __init__ class method.
        If you want to list all running process do the following:
        ins = Hack()
        print ins.running

        :processName: (string) Window title or process name.
        """
        system = winappdbg.System()
        for process in system:
            filename = process.get_filename()
            if filename is None:
                continue

            _name = filename.split("\\")[-1]
            _pid = process.get_pid()
            if pid is not None and _pid == pid:
                self.process = process
                self.name = _name
                self.pid = _pid

            elif name is not None and name == _name:
                self.process = process
                self.name = _name
                self.pid = _pid

            self.running.append((name, process.get_pid()))

    def get_base_address(self):
        """
        Get our processes base_address & its DLL's base_addresses too. \
        Then store it in the module_base_dict global variable.
        """
        process = self.process
        if process is None:
            raise ValueError("Could not find process.")
        # bits = process.get_bits()
        for module in process.iter_modules():
            if module.get_filename().split("\\")[-1] == self.name:
                self.base_address = module.get_base()
                # self.base_address = winappdbg.HexDump.address( module.get_base(), bits )
            else:
                module_name = os.path.basename(module.get_filename())
                self.module_base_dict[module_name] = module.get_base()
        try:
            self.set_last_address()
        except IndexError as e:
            pass

    def read(self, address, length):
        """
        Read process memory. (memory_adress, data_length). \
        i.e.: (0x40000000, 4)
        """
        process = self.process
        data = process.read(address, length)
        label = process.get_label_at_address(address)
        return data, label

    def read_char(self, address):
        return (self.process.read_char(address),
                self.process.get_label_at_address(address))

    def read_int(self, address):
        return (self.process.read_int(address),
                self.process.get_label_at_address(address))

    def read_uint(self, address):
        return (self.process.read_uint(address),
                self.process.get_label_at_address(address))

    def read_float(self, address):
        return (self.process.read_float(address),
                self.process.get_label_at_address(address))

    def read_double(self, address):
        return (self.process.read_double(address),
                self.process.get_label_at_address(address))

    def read_pointer(self, address):
        return (self.process.read_pointer(address),
                self.process.get_label_at_address(address))

    def read_dword(self, address):
        return (self.process.read_dword(address),
                self.process.get_label_at_address(address))

    def read_qword(self, address):
        return (self.process.read_qword(address),
                self.process.get_label_at_address(address))

    def read_structure(self, address):
        return (self.process.read_structure(address),
                self.process.get_label_at_address(address))

    def read_string(self, address, length):
        return (self.process.read_string(address, length),
                self.process.get_label_at_address(address))

    def write(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write(address, data)
        return written

    def write_char(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_char(address, data)
        return written

    def write_int(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_int(address, data)
        return written

    def write_uint(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_uint(address, data)
        return written

    def write_float(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_float(address, data)
        return written

    def write_double(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_double(address, data)
        return written

    def write_pointer(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_pointer(address, data)
        return written

    def write_dword(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_dword(address, data)
        return written

    def write_qword(self, address, data):
        "Write to process memory. (memory_address, data2write)"""
        process = self.process
        written = process.write_qword(address, data)
        return written

    def search(self, _bytes, minAddr, maxAddr):
        """
        Search minAddr through maxAddr for _bytes. (_bytes, minAddr, maxAddr).
        Returns a generator iterable containing memory addresses.
        """
        return self.process.search_bytes(_bytes, minAddr, maxAddr)

    def address_from_label(self, name):
        """Returns the memory address(es) that match the label name. (name)"""
        return self.process.resolve_label(name)

    def load_dll(self, filename):
        """Inject filename.dll into our process. (filename)"""
        process = self.process
        process.inject_dll(filename)
        return True

    def safe_exit(self):
        self.process.close_handle()
        return True

