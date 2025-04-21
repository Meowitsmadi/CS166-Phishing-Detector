#.venv\Scripts\activate.bat
# pip install streamlit
import streamlit as st

st.title("Phishing Link Detector")

# Text entry box
user_input = st.text_input("Enter the link to check:")

# Submit button
if st.button("Submit"):
    if user_input:
        st.success(f"Processing link: {user_input}")
        #Placee Holder value before we pass values to algorithim
    else:
        st.warning("Please enter a link before submitting.")