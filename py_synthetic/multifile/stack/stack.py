"""Stack - stack module with empty pop bug."""

class Stack:
    def __init__(self):
        self.items = []
    
    def push(self, item):
        self.items.append(item)
    
    def pop(self):
        return self.items.pop()  # BUG: No check for empty
    
    def peek(self):
        return self.items[-1]  # BUG: No check for empty

# Trigger
s = Stack()
result = s.pop()
