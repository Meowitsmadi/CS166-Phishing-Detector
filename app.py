import streamlit as st
from phishing_detector import phish_checker

st.title("Phishing Link Detector")

# Text entry box
user_input = st.text_input("Enter the link to check:")

# Submit button
if st.button("Submit"):
    if user_input:
        result = phish_checker(user_input)
        st.success(f"Result: {result}")
    else:
        st.warning("Please enter a link before submitting.")
