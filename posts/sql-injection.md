  SQL Injection: Attack Scenarios and Mitigations 

SQL Injection: Attack Scenarios and Mitigations
===============================================

Learn how SQL injection attacks work and how to prevent them in web applications.

What is SQL Injection?
----------------------

SQL Injection is a critical security vulnerability that allows attackers to interfere with the queries an application makes to its database. It typically occurs when user input is improperly handled and directly embedded into SQL queries.

Attackers can exploit SQL injection to bypass authentication, access or modify sensitive data, or even execute administrative database commands.

Attack Scenarios
----------------

Below are some common attack scenarios where SQL injection vulnerabilities can be exploited in web applications:

### Scenario 1: Vulnerable Python Code

The following Python code is vulnerable to SQL injection:

    import sqlite3
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    username = input("Enter username: ")
    password = input("Enter password: ")
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    if cursor.fetchone():
        print("Login successful")
    else:
        print("Login failed")

An attacker could enter `admin' --` to bypass authentication.

#### Fixed Version:

The secure Python code uses prepared statements to prevent SQL injection:

    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))

### Scenario 2: Vulnerable Node.js Code

The following Node.js code is vulnerable:

    app.get('/login', (req, res) => {
        let username = req.query.username;
        let password = req.query.password;
        let query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
        db.query(query, (err, result) => {
            if (result.length > 0) {
                res.send("Login successful");
            } else {
                res.send("Login failed");
            }
        });
    });

#### Fixed Version:

Using prepared statements in Node.js:

    app.get('/login', (req, res) => {
        let query = "SELECT * FROM users WHERE username = ? AND password = ?";
        db.query(query, [req.query.username, req.query.password], (err, result) => {
            if (result.length > 0) {
                res.send("Login successful");
            } else {
                res.send("Login failed");
            }
        });
    });

### Scenario 3: Vulnerable PHP Code

The following PHP code is vulnerable:

    <?php
    $conn = new mysqli("localhost", "root", "", "users");
    $username = $_GET['username'];
    $password = $_GET['password'];
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);
    if ($result->num_rows > 0) {
        echo "Login successful";
    } else {
        echo "Login failed";
    }
    ?>

#### Fixed Version:

Secure PHP code using prepared statements:

    <?php
    $conn = new mysqli("localhost", "root", "", "users");
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        echo "Login successful";
    } else {
        echo "Login failed";
    }
    ?>

Mitigation Strategies
---------------------

To prevent SQL injection vulnerabilities, follow these best practices:

*   **Use Prepared Statements:** Always use parameterized queries instead of string concatenation.
*   **Input Validation:** Validate user input to ensure it matches expected formats.
*   **Escape User Input:** Use functions like `mysqli_real_escape_string` (though prepared statements are preferred).
*   **Least Privilege:** Ensure database users have the minimum privileges required.