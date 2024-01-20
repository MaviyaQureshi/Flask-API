# classify.py
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
from feature_extraction1 import extract_features  # Import the feature extraction logic
from feature_extraction2 import extractfeatures2  # Import the feature extraction logic
from feature_extraction3 import extractfeatures3  # Import the feature extraction logic
from datetime import datetime

app = Flask(__name__)
CORS(app)


def classify_features1(features):
    # Load your pre-trained models from the .pkl files
    with open("./Models/set1/XGBoostClassify.pkl", "rb") as model_file:
        model1 = pickle.load(model_file)

    # Call the feature extraction function with the provided features
    extracted_features = extract_features(features)

    features_array = np.array(list(extracted_features.values())).reshape(1, -1)

    # Perform classification using your models
    result1 = model1.predict(features_array)

    return (int(result1[0]),)


def classify_features2(features):
    with open("./Models/Cleaned/XGBClassifier_1.pkl", "rb") as model_file:
        model1 = pickle.load(model_file)
    with open("./Models/Cleaned/LRClassifier_1.pkl", "rb") as model_file:
        model2 = pickle.load(model_file)
    with open("./Models/Cleaned/DTCClassifier_1.pkl", "rb") as model_file:
        model3 = pickle.load(model_file)
    with open("./Models/Cleaned/GNBClassifier_1.pkl", "rb") as model_file:
        model4 = pickle.load(model_file)
    with open("./Models/Cleaned/RFCClassifier_1.pkl", "rb") as model_file:
        model5 = pickle.load(model_file)
    with open("./Models/Cleaned/SVCClassifier_1.pkl", "rb") as model_file:
        model6 = pickle.load(model_file)
    with open("./Models/Cleaned/ABCClassifier_1.pkl", "rb") as model_file:
        model7 = pickle.load(model_file)

    # Call the feature extraction function with the provided features
    extracted_features = extractfeatures2(features)

    features_array = np.array(list(extracted_features.values())).reshape(1, -1)

    # Perform classification using your models
    result1 = model1.predict(features_array)
    result2 = model2.predict(features_array)
    result3 = model3.predict(features_array)
    result4 = model4.predict(features_array)
    result5 = model5.predict(features_array)
    result6 = model6.predict(features_array)
    result7 = model7.predict(features_array)

    return (
        int(result1[0]),
        int(result2[0]),
        int(result3[0]),
        int(result4[0]),
        int(result5[0]),
        int(result6[0]),
        int(result7[0]),
    )


def classify_features3(features):
    with open("./Models/Cleaned/XGBClassifier_copy.pkl", "rb") as model_file:
        model1 = pickle.load(model_file)
    with open("./Models/Cleaned/LRClassifier_copy.pkl", "rb") as model_file:
        model2 = pickle.load(model_file)
    with open("./Models/Cleaned/DTCClassifier_copy.pkl", "rb") as model_file:
        model3 = pickle.load(model_file)
    with open("./Models/Cleaned/GNBClassifier_copy.pkl", "rb") as model_file:
        model4 = pickle.load(model_file)
    with open("./Models/Cleaned/RFCClassifier_copy.pkl", "rb") as model_file:
        model5 = pickle.load(model_file)
    with open("./Models/Cleaned/SVCClassifier_copy.pkl", "rb") as model_file:
        model6 = pickle.load(model_file)
    # with open("./Models/Cleaned/MLPClassifier_copy.pkl", "rb") as model_file:
    #     model7 = pickle.load(model_file)

    # Call the feature extraction function with the provided features
    extracted_features = extractfeatures3(features)

    features_array = np.array(list(extracted_features.values())).reshape(1, -1)

    # Perform classification using your models
    result1 = model1.predict(features_array)
    result2 = model2.predict(features_array)
    result3 = model3.predict(features_array)
    result4 = model4.predict(features_array)
    result5 = model5.predict(features_array)
    result6 = model6.predict(features_array)
    # result7 = model7.predict(features_array)

    return (
        int(result1[0]),
        int(result2[0]),
        int(result3[0]),
        int(result4[0]),
        int(result5[0]),
        int(result6[0]),
        # int(result7[0]),
    )


@app.route("/classify", methods=["POST"])
def classification():
    try:
        # Receive JSON input
        request_data = request.get_json()

        # Ensure "url" key is present in the JSON data
        if "url" not in request_data:
            raise ValueError("Missing 'url' key in JSON data.")

        url = request_data["url"]

        # Perform classification using the feature extraction logic
        prediction = classify_features1(url)

        if prediction is not None:
            # Return the result as JSON
            return jsonify({"prediction": prediction})
        else:
            return jsonify({"error": "Failed to classify."})

    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/classification", methods=["POST"])
def classify():
    try:
        # Receive JSON input
        request_data = request.get_json()

        # Ensure "url" key is present in the JSON data
        if "url" not in request_data:
            raise ValueError("Missing 'url' key in JSON data.")

        url = request_data["url"]

        # Perform classification using the feature extraction logic
        prediction = classify_features2(url)

        if prediction is not None:
            # Return the result as JSON
            return jsonify({"prediction": prediction})
        else:
            return jsonify({"error": "Failed to classify."})

    except Exception as e:
        return jsonify({"error": str(e)})


# @app.route("/classifi", methods=["POST"])
# def classify2():
#     try:
#         # Receive JSON input
#         request_data = request.get_json()

#         # Ensure "url" key is present in the JSON data
#         if "url" not in request_data:
#             raise ValueError("Missing 'url' key in JSON data.")

#         url = request_data["url"]

#         # Perform classification using the feature extraction logic
#         prediction = classify_features3(url)

#         if prediction is not None:
#             # Return the result as JSON
#             return jsonify({"prediction": prediction})
#         else:
#             return jsonify({"error": "Failed to classify."})

#     except Exception as e:
#         return jsonify({"error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)
