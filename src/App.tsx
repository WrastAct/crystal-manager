import { useState, useEffect } from "react";
import reactLogo from "./assets/react.svg";
import "./App.css";
import { invoke } from "@tauri-apps/api";

function App() {
  const [pass, setPass] = useState("");
  const [isValid, setIsValid] = useState(false);

  const clickFunc = async () => {
    const result = await invoke<string>("read_file", { password: "passpass" });
    setPass(result);
  };

  const checkPassword = async () => {
    const result = await invoke<boolean>("password_exists");
    setIsValid(result);
  };

  useEffect(() => {
    checkPassword();
  })

  return (
    <div>
      <button onClick={checkPassword}>Check Password</button>
      {isValid && <button onClick={clickFunc}>Read File</button>}
      <div>{pass}</div>
    </div>
  );
}

export default App;
