import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions

logger = logging.getLogger(__name__)

def get_selenium_driver(headless=False):
    """
    Initializes and returns a Selenium WebDriver (Chrome or Firefox).
    Prioritizes Chrome, falling back to Firefox if Chrome fails.
    Requires chromedriver or geckodriver to be installed and accessible in PATH.
    Args:
        headless (bool): If True, run browser in headless mode.
    Returns:
        selenium.webdriver.remote.webdriver.WebDriver: The initialized WebDriver object.
    Raises:
        Exception: If no supported browser WebDriver can be initialized.
    """
    driver = None
    
    # --- Try Chrome first ---
    try:
        chrome_options = ChromeOptions()
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        if headless:
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
        
        driver = webdriver.Chrome(options=chrome_options)
        logger.info(f"[+] Chrome WebDriver launched successfully.")
        return driver

    except Exception as e:
        logger.warning(f"Chrome WebDriver failed to launch: {str(e)}. Falling back to Firefox. Ensure chromedriver is installed and in your system's PATH, or manually specify its path.")

    # --- Fallback to Firefox ---
    try:
        firefox_options = FirefoxOptions()
        if headless:
            firefox_options.add_argument("--headless")
        
        driver = webdriver.Firefox(options=firefox_options)
        logger.info(f"[+] Firefox WebDriver launched successfully.")
        return driver

    except Exception as e:
        logger.error(f"Firefox WebDriver failed: {str(e)}. No browser available. "
                     f"Please ensure geckodriver is installed and in your system's PATH, or manually specify its path.")
        raise Exception("No supported browser WebDriver found.")