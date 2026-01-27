"""Stack - queue variant with bug."""

class Queue:
    def __init__(self):
        self.items = []
    
    def enqueue(self, item):
        self.items.append(item)
    
    def dequeue(self):
        return self.items[0]  # BUG: No check for empty

# Trigger  
q = Queue()
result = q.dequeue()
