from flask import Flask, request, jsonify
import json
import re

app = Flask(__name__)

# Load WAF rules
with open('waf/rules/rules.json') as f:
    rules = json.load(f)

def detect_attack(input_data):
    for rule in rules:
        if re.search(rule['pattern'], input_data, re.IGNORECASE):
            return True, rule['description']
    return False, None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_malicious, description = detect_attack(user_input)
        if is_malicious:
            return jsonify({"status": "blocked", "reason": description}), 403
        return jsonify({"status": "allowed"}), 200
    return "WAF is running!"

if __name__ == '__main__':
    app.run(debug=True)
