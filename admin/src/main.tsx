import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import "normalize.css";
import "tailwindcss/tailwind.css";
import "./main.css";
import Home from "./home";

ReactDOM.createRoot(document.getElementById("root")).render(<App />);

function App() {
  return (
    <React.StrictMode>
      <Router basename={window.__ADMINPATH__}>
        <Routes>
          <Route path="/" element={<Home />}></Route>
        </Routes>
      </Router>
    </React.StrictMode>
  );
}
