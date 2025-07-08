# In cyber_main.py

import streamlit as st
import random
from quiz100 import malware_questions, pentest_questions, forensics_questions, cloud_questions, network_questions, vmware_questions, iot_questions, appsec_questions, reverse_engineering_questions, cryptography_questions
from quiz200 import malware_level2_questions, pentest_level2_questions, forensics_level2_questions, cloud_level2_questions, network_level2_questions, vmware_level2_questions, iot_level2_questions, appsec_level2_questions, reverse_engineering_level2_questions, cryptography_level2_questions

# Combine all questions (you can choose which level questions to include)
ALL_QUESTIONS = (
    malware_questions + pentest_questions + forensics_questions +
    cloud_questions + network_questions + vmware_questions +
    iot_questions + appsec_questions + reverse_engineering_questions +
    cryptography_questions
)

# You can also combine with level 2 questions if needed
# ALL_QUESTIONS += (
#     malware_level2_questions + pentest_level2_questions + forensics_level2_questions +
#     cloud_level2_questions + network_level2_questions + vmware_level2_questions +
#     iot_level2_questions + appsec_level2_questions + reverse_engineering_level2_questions +
#     cryptography_level2_questions
# )

# Helper function to score the quiz (copied from your quiz files)
def score_quiz(questions, user_answers):
    score = 0
    field_scores = {}
    for q in questions:
        correct = q["correct_answer"]
        user = user_answers.get(q["id"]) # Use question ID to retrieve answer
        if user == correct:
            score += 1
            field_scores[q["field"]] = field_scores.get(q["field"], 0) + 1
    return score, field_scores

# Helper function to recommend a field (copied from your quiz files)
def recommend_field(field_scores):
    if not field_scores:
        return "No strong recommendation"
    max_score = max(field_scores.values())
    top_fields = [field for field, score in field_scores.items() if score == max_score]
    return ", ".join(top_fields)

# Initialize session state for the quiz
if 'quiz_started' not in st.session_state:
    st.session_state.quiz_started = False
if 'current_question_index' not in st.session_state:
    st.session_state.current_question_index = 0
if 'user_answers' not in st.session_state:
    st.session_state.user_answers = {}
if 'selected_questions' not in st.session_state:
    # Shuffle and select a subset of questions if desired
    st.session_state.selected_questions = random.sample(ALL_QUESTIONS, k=10) # Example: 10 random questions
if 'quiz_finished' not in st.session_state:
    st.session_state.quiz_finished = False

st.title("Cybersecurity Quiz")

if not st.session_state.quiz_started:
    st.write("Welcome to the Cybersecurity Quiz! Test your knowledge across various cybersecurity domains.")
    if st.button("Start Quiz"):
        st.session_state.quiz_started = True
        st.session_state.current_question_index = 0
        st.session_state.user_answers = {}
        st.session_state.quiz_finished = False
        st.experimental_rerun() # Rerun to start the quiz

elif st.session_state.quiz_started and not st.session_state.quiz_finished:
    questions = st.session_state.selected_questions
    current_index = st.session_state.current_question_index

    if current_index < len(questions):
        current_question = questions[current_index]
        st.header(f"Question {current_index + 1}/{len(questions)}")
        st.write(current_question["question"])

        # Create a unique key for the radio button to prevent errors on rerun
        option_key = f"question_{current_question['id']}"
        user_choice = st.radio(
            "Select your answer:",
            current_question["options"],
            key=option_key
        )

        if st.button("Next Question"):
            # Store the user's answer
            st.session_state.user_answers[current_question["id"]] = user_choice
            st.session_state.current_question_index += 1
            if st.session_state.current_question_index >= len(questions):
                st.session_state.quiz_finished = True
            st.experimental_rerun() # Rerun to show the next question or results
    else:
        st.session_state.quiz_finished = True
        st.experimental_rerun() # Rerun to show results if all questions processed

elif st.session_state.quiz_finished:
    st.header("Quiz Completed!")
    total_score, field_scores = score_quiz(st.session_state.selected_questions, st.session_state.user_answers)
    recommended_field = recommend_field(field_scores)

    st.write(f"Your Total Score: {total_score}/{len(st.session_state.selected_questions)}")
    st.subheader("Field-wise Scores:")
    for field, score in field_scores.items():
        st.write(f"- {field}: {score} correct")

    st.success(f"Based on your answers, we recommend: **{recommended_field}**")

    if st.button("Restart Quiz"):
        st.session_state.quiz_started = False
        st.session_state.current_question_index = 0
        st.session_state.user_answers = {}
        st.session_state.quiz_finished = False
        st.session_state.selected_questions = random.sample(ALL_QUESTIONS, k=10) # Reselect questions for new quiz
        st.experimental_rerun()
