from datetime import datetime

FINE_PER_DAY = 0.50  # 50 cents per day

def calculate_fine(transaction_dict):
    """
    Calculates the fine if the book is returned after the due date.
    Expects a dictionary with 'return_date' and 'due_date' keys.
    """
    return_date = transaction_dict.get('return_date')
    due_date = transaction_dict.get('due_date')

    if return_date and due_date and return_date > due_date:
        delta = return_date - due_date
        return delta.days * FINE_PER_DAY
            
    return 0.0