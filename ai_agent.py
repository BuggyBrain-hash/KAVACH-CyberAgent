import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise ValueError("GROQ_API_KEY is not configured.")

client = OpenAI(
    api_key=api_key,
    base_url="https://api.groq.com/openai/v1"
)


def analyze_vulnerability(finding):

    prompt = f"""
You are the AI security analyst inside KAVACH CyberAgent.

Analyze this source-code security finding.

Vulnerability:
{finding['type']}

Severity:
{finding['severity']}

Line:
{finding['line']}

Code:
{finding['code']}

Scanner explanation:
{finding['description']}

Provide:

1. Security Risk
Explain why the code is dangerous.

2. Possible Impact
Explain what could happen if the vulnerability is exploited.

3. Recommended Fix
Explain how a developer should fix it.

4. Safer Example
Provide a small safer code example.

Do not execute the supplied code.
"""

    response = client.responses.create(
        model="openai/gpt-oss-20b",
        input=prompt
    )

    return response.output_text