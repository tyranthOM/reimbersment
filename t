// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
    apiKey: "AIzaSyAXSCZ2Wqv3Jw6diMNhX9KUMA3BWFgq_PI",
    authDomain: "reimbursement-a31af.firebaseapp.com",
    projectId: "reimbursement-a31af",
    storageBucket: "reimbursement-a31af.firebasestorage.app",
    messagingSenderId: "745043038117",
    appId: "1:745043038117:web:a0dd8aa3b22eda3355224c",
    measurementId: "G-PP8Y5J7NHR"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);







To host your site with Firebase Hosting, you need the Firebase CLI(a command
     line tool).

Run the following npm command to install the CLI or update to the latest CLI version.

npm install - g firebase - tools