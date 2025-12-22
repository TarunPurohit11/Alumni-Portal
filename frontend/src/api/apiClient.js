import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8080/api",  // Spring Boot port
  withCredentials: true,                 // important for OAuth cookies if used
});

export default api;
