import { useState, useEffect } from "react";
import "./App.css";
import { invoke } from "@tauri-apps/api";

function App() {
  const [passwordInput, setPasswordInput] = useState("");
  const [message, setMessage] = useState("");
  const [data, setData] = useState("");

  useEffect(() => {
    invoke<boolean>("data_exists").then((doesExist) => {
      if (doesExist) {
        setData("Data exists");
      } else {
        setData("No data");
      }
    });
  }, [setData]);

  const passwordChangeHandler = (event: any) => {
    setPasswordInput(event.target.value);
  };

  const submitHandler = async (event: any) => {
    event.preventDefault();

    const result = await invoke<boolean>("authenticate", {
      password: passwordInput,
    });
    if (result) {
      setMessage("Password matched or created!");
    } else {
      setMessage("Incorrect password");
    }
  };

  return (
    <div>
      <form onSubmit={submitHandler}>
        <label htmlFor="password">Password: </label>
        <input
          id="password"
          name="password"
          type={"text"}
          required
          minLength={8}
          value={passwordInput}
          onChange={passwordChangeHandler}
        />
        <button type="submit">Submit</button>
      </form>
      <div>{message}</div>
      <div>{data}</div>
    </div>
  );
}

export default App;
