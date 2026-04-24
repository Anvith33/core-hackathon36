from database import init_db, save_transaction, get_transactions

# Step 1: Create DB + table
init_db()

# Step 2: Insert test data
save_transaction("User1", "User2", 5000, "HIGH", ["Test transaction"])

# Step 3: Fetch and print
data = get_transactions()
print(data)