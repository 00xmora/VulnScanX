  CSRF: Attack Scenarios and Mitigations 

Cross-Site Request Forgery (CSRF): Attack Scenarios and Mitigations
===================================================================

Learn how CSRF attacks work and how to prevent them in web applications.

What is CSRF?
-------------

Cross-Site Request Forgery (CSRF), also known as XSRF, is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not data theft, since the attacker has no way to see the response to the forged request.

Successful CSRF attacks can compromise end-user data and operations. If the targeted end user is an administrator, CSRF can compromise the entire web application.

Attack Scenarios
----------------

Below are some common attack scenarios where CSRF vulnerabilities can be exploited in web applications:

### Scenario 1: Funds Transfer via GET Request

A banking application allows funds transfer via a GET request, like `https://bank.com/transfer?account=target&amount=1000`. An attacker can embed this URL in an image tag on a malicious site, and if a logged-in user visits the site, the transfer will occur without their explicit consent.

#### Vulnerable Implementation:

    // Vulnerable server-side handler for funds transfer (GET request)
    app.get('/transfer', (req, res) => {
        const { account, amount } = req.query;
        const userId = req.session.userId; // User is authenticated via session cookie
    
        // Perform transfer without CSRF token validation
        performFundsTransfer(userId, account, amount);
        res.send('Transfer successful!');
    });

#### Fixed Version:

The secure version requires a POST request and includes a CSRF token in the form.

    // Secure server-side handler for funds transfer (POST request with CSRF token)
    app.post('/transfer', (req, res) => {
        const { account, amount, csrf_token } = req.body;
        const userId = req.session.userId;
    
        // Validate CSRF token
        if (!isValidCsrfToken(csrf_token, req.session.csrf_token)) {
            return res.status(403).send('Invalid CSRF token.');
        }
    
        performFundsTransfer(userId, account, amount);
        res.send('Transfer successful!');
    });
    
    // Example HTML form for the secure version
    <form action="/transfer" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="text" name="account" value="Target Account">
        <input type="text" name="amount" value="1000">
        <button type="submit">Transfer Funds</button>
    </form>

### Scenario 2: Changing Email Address

A user profile page allows changing the email address via a POST request. If no CSRF protection is in place, an attacker can create a malicious page with a hidden form that automatically submits to the target application's email change endpoint, updating the victim's email to one controlled by the attacker.

#### Vulnerable Implementation (Malicious Page Example):

    <html>
    <body onload="document.forms[0].submit()">
      <form action="https://vulnerable-site.com/change_email" method="POST">
        <input type="hidden" name="new_email" value="attacker@example.com" />
        <input type="hidden" name="confirm_email" value="attacker@example.com" />
      </form>
    </body>
    </html>

#### Fixed Version:

Implementing and validating a unique CSRF token for each state-changing request.

    // Server-side pseudocode for handling email change with CSRF token
    app.post('/change_email', (req, res) => {
        const { new_email, confirm_email, csrf_token } = req.body;
        const userId = req.session.userId;
    
        if (!isValidCsrfToken(csrf_token, req.session.csrf_token)) {
            return res.status(403).send('Invalid CSRF token.');
        }
    
        if (new_email === confirm_email) {
            updateUserEmail(userId, new_email);
            res.send('Email updated successfully!');
        } else {
            res.status(400).send('Emails do not match.');
        }
    });
    
    // Corresponding HTML form on the legitimate site
    <form action="/change_email" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <label for="new_email">New Email:</label>
        <input type="email" id="new_email" name="new_email" required><br>
        <label for="confirm_email">Confirm Email:</label>
        <input type="email" id="confirm_email" name="confirm_email" required><br>
        <button type="submit">Change Email</button>
    </form>

Mitigation Strategies
---------------------

To prevent CSRF vulnerabilities, follow these best practices:

*   **CSRF Tokens:** Implement anti-CSRF tokens for all state-changing requests. These tokens should be unique, unpredictable, and associated with the user's session. They should be validated on the server-side.
*   **SameSite Cookies:** Use the \`SameSite\` attribute on cookies to restrict when cookies are sent with cross-site requests. Setting \`SameSite=Lax\` or \`Strict\` can significantly mitigate CSRF.
*   **Referer Header Validation:** Validate the \`Referer\` header to ensure that requests originate from your domain. While not foolproof (can be spoofed or missing), it adds another layer of defense.
*   **Custom Headers:** For AJAX requests, use custom request headers (e.g., \`X-Requested-With\`) that cannot be set by cross-origin requests.
*   **User Re-authentication:** For highly sensitive operations (e.g., password change, funds transfer), require the user to re-enter their password.