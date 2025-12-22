import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams, useNavigate } from "react-router-dom";

const api = axios.create({
  baseURL: "http://localhost:8080",
});

// Interceptor to add Token automatically
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default function GroupAssessmentPage() {
  const { groupId } = useParams();
  const navigate = useNavigate();
  const [questions, setQuestions] = useState([]);
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
  api.get(`/api/assessment/generate/${groupId}`)
    .then(res => {
      let dataStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

      // Remove any backticks or ```json markers
      dataStr = dataStr.replace(/```(json)?/g, '').trim();

      // Now safely parse
      const data = JSON.parse(dataStr);

      setQuestions(data.questions);
      setLoading(false);
    })
    .catch(err => {
      console.error("Error loading assessment:", err);
      alert("Failed to generate assessment. Please try again.");
      navigate("/tech-groups");
    });
}, [groupId, navigate]);



  const submitTest = async () => {
    try {
      // Send answers (user selections) AND questions (for correct keys)
      const res = await api.post(`/api/assessment/submit/${groupId}`, {
        answers,
        questions 
      });

      if (res.data.passed) {
        alert(`Congratulations! You passed with ${res.data.score}%.`);
        navigate(`/groups/${groupId}/view`);
      } else {
        alert(`Assessment failed. Score: ${res.data.score}%. You can try again later.`);
        navigate("/tech-groups");
      }
    } catch (err) {
      console.error("Submission error:", err);
      alert(err.response?.data?.message || "Failed to submit test.");
    }
  };

  if (loading) return <p className="p-10 text-center font-semibold">Generating your assessment test...</p>;

  return (
    <div className="min-h-screen bg-gray-100 flex justify-center p-6 pt-12">
      <div className="bg-white w-full max-w-3xl p-8 rounded-xl shadow-lg border border-gray-200">
        <h1 className="text-2xl font-bold mb-2 text-gray-900">
          Group Entry Assessment
        </h1>
        <p className="text-gray-500 mb-6 border-b pb-4 text-sm italic">
          Pass score required: 70%
        </p>

        {questions.map((q, index) => (
          <div key={index} className="mb-8 p-4 bg-gray-50 rounded-lg border border-gray-100">
            <p className="font-bold text-gray-800 mb-3">
              {index + 1}. {q.question}
            </p>

            {Object.entries(q.options).map(([key, value]) => (
              <label key={key} className="flex items-center mb-3 cursor-pointer hover:text-indigo-600 transition">
                <input
                  type="radio"
                  name={`q-${index}`}
                  value={key}
                  checked={answers[index] === key}
                  onChange={() =>
                    setAnswers({ ...answers, [index]: key })
                  }
                  className="mr-3 w-4 h-4 text-indigo-600"
                />
                <span className="text-gray-700">
                  <span className="font-semibold">{key}.</span> {value}
                </span>
              </label>
            ))}
          </div>
        ))}

        <button
          onClick={submitTest}
          disabled={Object.keys(answers).length < questions.length}
          className="w-full bg-indigo-600 text-white px-6 py-3 rounded-lg font-bold text-lg hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition"
        >
          Submit Test
        </button>
      </div>
    </div>
  );
}