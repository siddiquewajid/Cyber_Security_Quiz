
import streamlit as st
import random
from QUIZ100 import *
from QUIZ200 import *

st.set_page_config(page_title="Cybersecurity Quiz App", layout="centered")

def show_quiz(questions, level_name):
    st.title(f"{level_name} Quiz")
    score = 0
    random.shuffle(questions)
    for i, q in enumerate(questions):
        st.subheader(f"Q{i+1}: {q['question']}")
        user_answer = st.radio("Choose an option:", q["options"], key=q["id"])
        if user_answer == q["correct_answer"]:
            score += 1

    st.success(f"Your Score: {score}/{len(questions)}")
    return score

def main():
    st.sidebar.title("Quiz Navigation")
    stage = st.sidebar.radio("Select Quiz Level:", ["Level 1", "Level 2"])

    if stage == "Level 1":
        st.header("Level 1: Basic Cybersecurity Quiz")
        field = st.selectbox("Choose your field of interest:", list(level1_fields.keys()))
        if field:
            if st.button("Start Level 1 Quiz"):
                show_quiz(level1_fields[field], "Level 1")
                st.session_state['recommended'] = field

    elif stage == "Level 2":
        st.header("Level 2: Advanced Cybersecurity Quiz")
        if 'recommended' not in st.session_state:
            st.warning("Please complete Level 1 to unlock Level 2.")
            return

        field = st.session_state['recommended']
        st.info(f"Level 2 Quiz is based on your recommended field: {field}")

        if st.button("Start Level 2 Quiz"):
            show_quiz(level2_fields[field], "Level 2")

if __name__ == "__main__":
    # Define level 1 and level 2 field mappings
    level1_fields = {
        "Malware Analysis": malware_questions,
        "Penetration Testing": pentest_questions,
        "Digital Forensics": forensics_questions,
        "Cloud Security": cloud_questions,
        "Network Security": network_questions,
        "VMware Security": vmware_questions,
        "IoT Security": iot_questions,
        "Application Security": appsec_questions,
        "Reverse Engineering": reverse_engineering_questions,
        "Cryptography": cryptography_questions,
    }

    level2_fields = {
        "Malware Analysis": malware_level2_questions,
        "Penetration Testing": pentest_level2_questions,
        "Digital Forensics": forensics_level2_questions,
        "Cloud Security": cloud_level2_questions,
        "Network Security": network_level2_questions,
        "VMware Security": vmware_level2_questions,
        "IoT Security": iot_level2_questions,
        "Application Security": appsec_level2_questions,
        "Reverse Engineering": reverse_engineering_level2_questions,
        "Cryptography": cryptography_level2_questions,
    }

    main()
