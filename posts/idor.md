  IDOR: Attack Scenarios and Mitigations 

Insecure Direct Object Reference (IDOR): Attack Scenarios and Mitigations
=========================================================================

Learn how IDOR vulnerabilities work and how to prevent them in web applications.

What is IDOR?
-------------

Insecure Direct Object Reference (IDOR) is a type of access control vulnerability that occurs when an application provides direct access to objects based on user-supplied input. This means an attacker can manipulate parameters that directly refer to objects (like database keys, filenames, or directory paths) and gain unauthorized access to data or functionality.

IDOR vulnerabilities can lead to unauthorized information disclosure, modification, or deletion of data.

Attack Scenarios
----------------

Below are some common attack scenarios where IDOR vulnerabilities can be exploited in web applications:

### Scenario 1: Direct Object Reference in URL Parameter

A vulnerable application might expose user profile information using a URL like `https://example.com/profile?id=123`. If an attacker changes the `id` parameter to `124`, they might gain access to another user's profile without proper authorization checks.

#### Vulnerable Implementation:

    // Pseudocode for a vulnerable profile retrieval
    function getUserProfile(userId) {
        // No authorization check; directly fetches user data based on ID
        $user_data = database.fetch("SELECT * FROM users WHERE id = ?", userId);
        return $user_data;
    }
    
    // In a web route:
    app.get('/profile', (req, res) => {
        const userId = req.query.id; // User-supplied ID
        const profile = getUserProfile(userId); // Directly use the ID
        res.render('profile', { profile });
    });

#### Fixed Version:

The secure version includes an authorization check to ensure the logged-in user is authorized to view the requested profile.

    // Pseudocode for a secure profile retrieval
    function getUserProfile(requestedUserId, loggedInUserId) {
        // Ensure the logged-in user is authorized to view this profile
        if (requestedUserId !== loggedInUserId && !userIsAdmin(loggedInUserId)) {
            throw new Error("Unauthorized access");
        }
        $user_data = database.fetch("SELECT * FROM users WHERE id = ?", requestedUserId);
        return $user_data;
    }
    
    // In a web route:
    app.get('/profile', (req, res) => {
        const requestedUserId = req.query.id;
        const loggedInUserId = req.session.userId; // Get ID of currently logged-in user
        try {
            const profile = getUserProfile(requestedUserId, loggedInUserId);
            res.render('profile', { profile });
        } catch (error) {
            res.status(403).send(error.message); // Forbidden
        }
    });

### Scenario 2: Insecure File Access

An application allows users to download invoices via a URL like `https://example.com/download?file=invoice_user_123.pdf`. If the application directly uses the \`file\` parameter without validating user authorization, an attacker could attempt to download \`invoice\_user\_124.pdf\` or even \`../../../../etc/passwd\`.

#### Vulnerable Implementation:

    <?php
    // Insecure PHP file download script
    $filename = $_GET['file'];
    readfile("/var/www/invoices/" . $filename); // Directly serving file based on user input
    ?>

#### Fixed Version:

The secure version validates the requested file against a list of files the user is authorized to access, or generates a unique, unguessable ID for each file.

    <?php
    // Secure PHP file download script
    $requestedFile = $_GET['file'];
    $userId = $_SESSION['user_id']; // Get logged-in user's ID
    
    // Assume a function that retrieves authorized files for the current user
    $authorizedFiles = getUserAuthorizedFiles($userId); 
    
    if (in_array($requestedFile, $authorizedFiles)) {
        // Ensure filename does not contain directory traversal characters
        $safeFilename = basename($requestedFile); 
        readfile("/var/www/invoices/" . $safeFilename);
    } else {
        http_response_code(403); // Forbidden
        echo "Access denied.";
    }
    ?>

Mitigation Strategies
---------------------

To prevent IDOR vulnerabilities, follow these best practices:

*   **Implement Robust Access Control:** Always verify that the authenticated user is authorized to access the requested resource. This is the most crucial step.
*   **Use Indirect References:** Instead of exposing direct object IDs to the user, use indirect references (e.g., GUIDs or hashed IDs) that map to the actual IDs on the server-side.
*   **Validate All User Input:** Especially for parameters that refer to objects, rigorously validate their values against expected formats and authorized ranges.
*   **Least Privilege:** Ensure that database queries and file access operations are performed with the minimum necessary privileges.
*   **Session-based Access Control:** Rely on server-side session data to determine user privileges, rather than client-side parameters.