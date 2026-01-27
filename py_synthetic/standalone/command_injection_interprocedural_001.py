"""Complex Interprocedural Command Injection: Data flow through classes"""

class CommandBuilder:
    """Helper class for building shell commands"""
    def __init__(self):
        self.parts = []
    
    def add_command(self, cmd):
        self.parts.append(cmd)
        return self
    
    def add_arg(self, arg):
        self.parts.append(arg)
        return self
    
    def build(self):
        return ' '.join(self.parts)

class SystemExecutor:
    """Executes system commands"""
    def run(self, command):
        import os
        os.system(command)  # BUG: Executes tainted command

def process_file(filename):
    """BUG: Complex interprocedural command injection through classes"""
    import sys
    user_file = sys.argv[1] if len(sys.argv) > 1 else "test.txt"
    
    builder = CommandBuilder()
    builder.add_command('cat').add_arg(user_file)  # Taint flows into builder
    cmd = builder.build()  # Taint flows to command string
    
    executor = SystemExecutor()
    executor.run(cmd)  # BUG: Tainted command executed

if __name__ == '__main__':
    process_file("test")
