import { useState, useEffect } from "react";
import "./App.css";
import { invoke } from "@tauri-apps/api";

function App() {
  const [pass, setPass] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [isValid, setIsValid] = useState(false);

  const clickFunc = async () => {
    const result = await invoke<string>("read_file", { password: "passpass" });
    setPass(result);
  };

  const changePasswordHandler = (event: any) => {
    setPasswordInput(event.target.value);
  };

  const checkPassword = async () => {
    const result = await invoke<boolean>("password_exists");
    setIsValid(result);
  };

  const enterPassword = async () => {
    const result = await invoke<boolean>("enter_password", { password: passwordInput});
    console.log(result);
  }

  useEffect(() => {
    checkPassword();
  });

  return (
    <div>
      <form>
        <label htmlFor="passwordInput">Password:</label>
        <input
          type="text"
          id="passwordInput"
          name="passwordInput"
          onChange={changePasswordHandler}
          value={passwordInput}
        />
      </form>
      <button onClick={enterPassword}>Check Password</button>
      {isValid && <button onClick={clickFunc}>Read File</button>}
      <div>{pass}</div>
    </div>
  );
}

export default App;
