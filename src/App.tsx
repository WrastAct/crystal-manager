import { useState } from 'react'
import reactLogo from './assets/react.svg'
import './App.css'
import { invoke } from "@tauri-apps/api"

function App() {
  const [pass, setPass] = useState("");

  const clickFunc = () => {
    invoke("read_file", {password: "passpass"}).then((p) => {
      console.log(p);
      setPass(JSON.stringify(p));
    })
  }

  return (
    <div>
      <button onClick={clickFunc}>{pass}</button>
    </div>
  )
}

export default App
