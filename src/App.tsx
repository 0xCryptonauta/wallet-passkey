// src/App.tsx
import { Navbar } from "./components/Navbar";
import { Signature } from "./components/Signature";

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <Signature />
    </div>
  );
}

export default App;
