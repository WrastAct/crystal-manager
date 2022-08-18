import { useState, useEffect } from "react";
import "./App.css";
import { invoke } from "@tauri-apps/api";

function App() {
  const [pass, setPass] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [isValid, setIsValid] = useState(false);
  const [json, setJson] = useState("");
  const [base64json, setBase64Json] = useState("");
  const [decryptedJson, setDecryptedJson] = useState("");

  const clickFunc = async () => {
    const result = await invoke<string>("read_file", { password: "passpass" });
    setPass(result);
  };

  const changePasswordHandler = (event: any) => {
    setPasswordInput(event.target.value);
  };

  const changeJsonHandler = (event: any) => {
    setJson(event.target.value);
  };

  const checkPassword = async () => {
    const result = await invoke<boolean>("password_exists");
    setIsValid(result);
  };

  const checkJson = async () => {
    const result = await invoke<string>("encrypt_json", { json: json, password: passwordInput });
    setBase64Json(result);
    console.log(result);

    const decResult = await invoke<string>("decrypt_json", { encryptedJson: result, password: passwordInput});
    setDecryptedJson(decResult);
    console.log(decResult);
  }

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
        <label htmlFor="jsonInput">Jason:</label>
        <input
          type="text"
          id="jsonInput"
          name="jsonInput"
          onChange={changeJsonHandler}
          value={json}
        />
      </form>
      <button onClick={enterPassword}>Check Password</button>
      {isValid && <button onClick={clickFunc}>Read File</button>}
      <button onClick={checkJson}>Check Json</button>
      <div>{pass}</div>
      <div>{base64json}</div>
      <div>{decryptedJson}</div>
    </div>
  );
}

export default App;
