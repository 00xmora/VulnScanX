  Command Injection: Attack Scenarios and Mitigations 

Command Injection: Attack Scenarios and Mitigations
===================================================

Learn how command injection attacks work and how to prevent them in web applications.

What is Command Injection?
--------------------------

Command Injection is a critical security vulnerability that occurs when an attacker can execute arbitrary commands on the host operating system through a vulnerable application. This vulnerability typically arises when user input is improperly sanitized and passed to a system shell.

Attackers can exploit command injection to gain unauthorized access to sensitive data, compromise the server, or even take control of the entire system.

Attack Scenarios
----------------

Below are some common attack scenarios where command injection vulnerabilities can be exploited in web applications:

### Scenario 1: Vulnerable User Input in Python

Vulnerable Python code that uses `os.system` to execute user input:

    import os
    
    user_input = input("Enter your name: ")
    os.system(f"echo Hello {user_input}")

This code is vulnerable to command injection, where an attacker could enter something like `; rm -rf /`, causing unwanted system commands to run.

#### Fixed Version:

The fixed Python code uses `subprocess.run` for better security:

    import subprocess
    
    user_input = input("Enter your name: ")
    subprocess.run(["echo", f"Hello {user_input}"], check=True)

The user input is safely handled as part of a list of arguments passed to `subprocess.run`, which avoids shell injection.

### Scenario 2: Vulnerable PHP Script

Vulnerable PHP code that passes user input directly to `system`:

    <?php
    $user_input = $_GET['input'];
    system("echo " . $user_input);
    ?>

This code allows an attacker to execute arbitrary commands by sending input like `?input=; cat /etc/passwd`.

#### Fixed Version:

The fixed PHP code uses `escapeshellarg` to sanitize the user input:

    <?php
    $user_input = escapeshellarg($_GET['input']);
    system("echo $user_input");
    ?>

The `escapeshellarg` function escapes any potentially dangerous characters in the input, preventing command injection.

### Scenario 3: Node.js Command Injection

Vulnerable Node.js code using `exec` with user input:

    const { exec } = require('child_process');
    const user_input = req.body.input;
    exec(`echo ${user_input}`);

An attacker could inject commands like `; ls -la` into the user input and execute unintended actions.

#### Fixed Version:

The fixed Node.js code uses an array of arguments with `exec` to prevent injection:

    const { exec } = require('child_process');
    const user_input = req.body.input;
    exec(["echo", user_input], (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return;
      }
      console.log(stdout);
    });

By passing the user input as an array of arguments, we avoid directly embedding the input into the shell command, reducing the risk of command injection.

Mitigation Strategies
---------------------

To prevent command injection vulnerabilities, follow these best practices:

*   **Input Validation:** Always validate and sanitize user input to ensure it does not contain malicious commands. Use allowlists to restrict input to known safe values.
*   **Use Safe APIs:** Avoid passing user input directly to system shells. Use safer alternatives like `subprocess.run` in Python, `system` with escapeshellarg in PHP, or `exec` with an array of arguments in Node.js.
*   **Escape Shell Metacharacters:** In PHP, use functions like `escapeshellcmd` and `escapeshellarg` to escape potentially dangerous characters.