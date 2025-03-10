import React from "react";
import { Route, Routes } from "react-router-dom";
import Register from "./components/Register";
import Home from "./components/Home";
import Login from "./components/Login";
import AdminDashboard from "./Pages/AdminDashboard";
import JobSeekerDashboard from "./Pages/JobSeekerDashboard";
import RecruiterDashboard from "./Pages/RecruiterDashboard";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Register />} />
      <Route path="/home" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/admin-dashboard" element={<AdminDashboard />} />
      <Route path="/job-seeker-dashboard" element={<JobSeekerDashboard />} />
      <Route path="/recruiter-dashboard" element={<RecruiterDashboard />} />
    </Routes>
  );
}

export default App;
