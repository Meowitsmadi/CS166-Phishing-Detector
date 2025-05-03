import streamlit as st
from phishing_detector import phish_checker
from dataset import X, y  # Import dataset features and targets
from analyze_emails import analyze_email  # Assuming analyze_emails is defined in email_analyzer.py
from search_dbs import retrieve_url_analysis

st.title("Phishing Detector")

# Sidebar for mode selection
mode = st.sidebar.selectbox("Choose a mode:", ["Analyze URL", "Analyze Email", "Dataset Overview"])

if mode == "Analyze URL":
    # Text entry box for URL analysis
    user_input = st.text_input("Enter the link to check:")
    if st.button("Submit URL"):
        if user_input:
            result = phish_checker(user_input)
            api_result = retrieve_url_analysis(user_input)

            st.write("**Analyzing your link with our own detection algorithm...**")
            st.success(f"Result: {result}")

            st.write("**Analyzing your link with the VirusTotal API...**")
            st.success(f"Result: {api_result}")

        else:
            st.warning("Please enter a link before submitting.")

elif mode == "Analyze Email":
    # File uploader for email analysis
    uploaded_file = st.file_uploader("Upload the email file to analyze:", type=["eml"])
    if st.button("Submit Email"):
        if uploaded_file:
            # Read the uploaded file as a string
            email_string = uploaded_file.getvalue().decode("utf-8")
            email_result = analyze_email(email_string)
            st.success(f"Email Analysis Result: {email_result}")
        else:
            st.warning("Please upload an email file before submitting.")

elif mode == "Dataset Overview":
    # Display dataset information
    st.subheader("Dataset Overview")
    st.write("This dataset contains legitimate and phishing URLs.")
    st.write("**Features (X):**")
    st.dataframe(X.head())  # Display the first few rows of features
    st.write("**Targets (y):**")
    st.dataframe(y.head())  # Display the first few rows of targets

    