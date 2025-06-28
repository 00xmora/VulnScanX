  Advanced XSS Vulnerability Examples: JavaScript and PHP 

Advanced XSS Vulnerability Examples: JavaScript and PHP
=======================================================

Detailed advanced examples of reflected, stored, and DOM-based XSS vulnerabilities in both JavaScript and PHP—including vulnerable implementations and secure fixes.

Advanced XSS Examples in JavaScript
-----------------------------------

### 1\. Advanced Reflected XSS in JavaScript

This example simulates a search results page where user input is directly reflected in the output. Attackers can craft a URL (e.g., `?q=<script>alert('XSS')</script>`) that injects malicious code.

#### Vulnerable Version:

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Search Page - Vulnerable Reflected XSS</title>
    </head>
    <body>
      <h1>Search Results</h1>
      <div id="results"></div>
      <script>
        // Extract query parameter 'q' from URL
        const params = new URLSearchParams(window.location.search);
        const query = params.get('q');
        // Vulnerable: directly inserting unsanitized user input into innerHTML
        document.getElementById('results').innerHTML =
          "You searched for: " + query + "Results: " + performSearch(query);
        
        function performSearch(term) {
          // Simulated search function returning HTML content
          return "Result for " + term + "";
        }
      </script>
    </body>
    </html>
    

#### Fixed Version:

The secure version uses safe DOM methods and manual encoding to prevent any injected scripts from executing.

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Search Page - Secured Reflected XSS</title>
    </head>
    <body>
      <h1>Search Results</h1>
      <div id="results"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const query = params.get('q') || "";
        const resultsDiv = document.getElementById('results');
        
        // Create a paragraph element and set its text content
        const searchInfo = document.createElement('p');
        searchInfo.textContent = "You searched for: " + query;
        resultsDiv.appendChild(searchInfo);
        
        // For the simulated search result, ensure any dynamic text is safely encoded
        function performSafeSearch(term) {
          // Replace < and > with HTML entities
          return "Result for " + term.replace(//g, ">") + "";
        }
        const resultPara = document.createElement('p');
        // If the search result contains safe HTML from a trusted source, you might use innerHTML;
        // otherwise, use textContent. Here we assume the wrapping HTML is safe.
        resultPara.innerHTML = "Results: " + performSafeSearch(query);
        resultsDiv.appendChild(resultPara);
      </script>
    </body>
    </html>
    

### 2\. Advanced Stored XSS in JavaScript (Using localStorage)

In this example, comments are stored in `localStorage` and later rendered on the page. Without proper sanitization, an attacker can inject a script that will execute whenever the comments are viewed.

#### Vulnerable Version:

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Comment Board - Vulnerable Stored XSS</title>
    </head>
    <body>
      <h1>Comment Board</h1>
      <form id="commentForm">
        <input type="text" id="comment" placeholder="Enter comment">
        <button type="submit">Submit</button>
      </form>
      <div id="comments"></div>
      
      <script>
        // Load stored comments from localStorage
        let comments = JSON.parse(localStorage.getItem('comments')) || [];
        const commentsDiv = document.getElementById('comments');
        comments.forEach(function(comment) {
          let p = document.createElement('p');
          // Vulnerable: inserting unsanitized comment as HTML
          p.innerHTML = comment;
          commentsDiv.appendChild(p);
        });
        
        document.getElementById('commentForm').addEventListener('submit', function(e) {
          e.preventDefault();
          let newComment = document.getElementById('comment').value;
          comments.push(newComment);
          localStorage.setItem('comments', JSON.stringify(comments));
          let p = document.createElement('p');
          p.innerHTML = newComment;
          commentsDiv.appendChild(p);
        });
      </script>
    </body>
    </html>
    

#### Fixed Version:

By rendering comments as plain text, the browser treats any HTML tags as text rather than executable code.

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Comment Board - Secured Stored XSS</title>
    </head>
    <body>
      <h1>Comment Board</h1>
      <form id="commentForm">
        <input type="text" id="comment" placeholder="Enter comment">
        <button type="submit">Submit</button>
      </form>
      <div id="comments"></div>
      
      <script>
        let comments = JSON.parse(localStorage.getItem('comments')) || [];
        const commentsDiv = document.getElementById('comments');
        comments.forEach(function(comment) {
          let p = document.createElement('p');
          // Secure: use textContent to avoid executing embedded HTML
          p.textContent = comment;
          commentsDiv.appendChild(p);
        });
        
        document.getElementById('commentForm').addEventListener('submit', function(e) {
          e.preventDefault();
          let newComment = document.getElementById('comment').value;
          comments.push(newComment);
          localStorage.setItem('comments', JSON.stringify(comments));
          let p = document.createElement('p');
          p.textContent = newComment;
          commentsDiv.appendChild(p);
        });
      </script>
    </body>
    </html>
    

### 3\. Advanced DOM-Based XSS in JavaScript

In a DOM-based XSS attack, the client-side script directly uses data from the URL (e.g., the hash) to modify the page’s DOM. An attacker might pass a malicious payload in the URL fragment.

#### Vulnerable Version:

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Dynamic Profile - Vulnerable DOM XSS</title>
    </head>
    <body>
      <h1>User Profile</h1>
      <div id="profile"></div>
      <script>
        // Get parameters from URL hash (e.g., #name=John&bio=<script>alert('XSS')</script>)
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const name = params.get('name') || 'Guest';
        const bio = params.get('bio') || 'No bio provided';
        
        // Vulnerable: unsanitized insertion into innerHTML
        document.getElementById('profile').innerHTML =
          "<h2>" + name + "</h2><p>" + bio + "</p>";
      </script>
    </body>
    </html>
    

#### Fixed Version:

Using safe DOM methods like `createTextNode` or setting `textContent` ensures that injected data is rendered as plain text.

    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Dynamic Profile - Secured DOM XSS</title>
    </head>
    <body>
      <h1>User Profile</h1>
      <div id="profile"></div>
      <script>
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const name = params.get('name') || 'Guest';
        const bio = params.get('bio') || 'No bio provided';
        
        const profileDiv = document.getElementById('profile');
        const nameElem = document.createElement('h2');
        nameElem.textContent = name;
        const bioElem = document.createElement('p');
        bioElem.textContent = bio;
        
        profileDiv.appendChild(nameElem);
        profileDiv.appendChild(bioElem);
      </script>
    </body>
    </html>
    

Advanced XSS Examples in PHP
----------------------------

### 1\. Advanced Reflected XSS in PHP

This PHP example simulates a search functionality where a query parameter is reflected in the output. An attacker can inject HTML or JavaScript into the response.

#### Vulnerable Version:

    <?php
    // File: search.php
    $query = $_GET['q'] ?? '';
    echo "<h1>Search Results</h1>";
    echo "<p>You searched for: $query</p>";
    
    function search($term) {
      // Vulnerable: directly embedding user input in HTML
      return "Found result for $term";
    }
    echo "<div>" . search($query) . "</div>";
    ?>
    

#### Fixed Version:

Using `htmlspecialchars` ensures that any user-supplied content is safely encoded before output.

    <?php
    $query = $_GET['q'] ?? '';
    echo "<h1>Search Results</h1>";
    echo "<p>You searched for: " . htmlspecialchars($query, ENT_QUOTES, 'UTF-8') . "</p>";
    
    function search($term) {
      // Secure: encode user input before embedding it in HTML
      return "Found result for " . htmlspecialchars($term, ENT_QUOTES, 'UTF-8') . "";
    }
    echo "<div>" . search($query) . "</div>";
    ?>
    

### 2\. Advanced Stored XSS in PHP

In this example, user comments stored in a simulated database are output on the page without proper sanitization, enabling stored XSS.

#### Vulnerable Version:

    <?php
    // Simulated database retrieval
    $comments = [
      "<script>alert('XSS')</script>",
      "This is a normal comment."
    ];
    
    echo "<h1>User Comments</h1>";
    foreach ($comments as $comment) {
      // Vulnerable: direct output without encoding
      echo "<p>$comment</p>";
    }
    ?>
    

#### Fixed Version:

By applying `htmlspecialchars` to each comment, any malicious scripts are rendered inert.

    <?php
    $comments = [
      "<script>alert('XSS')</script>",
      "This is a normal comment."
    ];
    
    echo "<h1>User Comments</h1>";
    foreach ($comments as $comment) {
      echo "<p>" . htmlspecialchars($comment, ENT_QUOTES, 'UTF-8') . "</p>";
    }
    ?>
    

### 3\. Advanced DOM-Based XSS in PHP

While DOM-based XSS is primarily a client-side concern, PHP can inadvertently enable it by embedding unsanitized user data into JavaScript. Here, a PHP variable is injected directly into a script block.

#### Vulnerable Version:

    <?php
    // File: dashboard.php
    $data = $_GET['data'] ?? '';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Dashboard - Vulnerable Embedded XSS</title>
    </head>
    <body>
      <h1>Dashboard</h1>
      <div id="output"></div>
      <script>
        // Vulnerable: unsanitized PHP variable is embedded into JavaScript
        var userData = "";
        document.getElementById('output').innerHTML = "User Data: " + userData;
      </script>
    </body>
    </html>
    

#### Fixed Version:

Using `json_encode` to safely pass PHP data to JavaScript ensures that any special characters are properly escaped.

    <?php
    $data = $_GET['data'] ?? '';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Dashboard - Secured Embedded XSS</title>
    </head>
    <body>
      <h1>Dashboard</h1>
      <div id="output"></div>
      <script>
        // Secure: using json_encode to safely embed PHP data into JavaScript
        var userData = ;
        document.getElementById('output').textContent = "User Data: " + userData;
      </script>
    </body>
    </html>
    

Mitigation Strategies for XSS
-----------------------------

To safeguard your applications from XSS vulnerabilities:

*   **Input Validation and Sanitization:** Validate all incoming data and use allowlists when possible.
*   **Output Encoding:** Encode user-supplied data before rendering it (e.g., using `htmlspecialchars` in PHP or text nodes in JavaScript).
*   **Content Security Policy (CSP):** Implement a strong CSP to restrict executable sources.
*   **Use Secure Frameworks:** Leverage frameworks that include built-in security features and automatic escaping.