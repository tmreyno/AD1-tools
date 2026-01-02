/* @refresh reload */
import { render } from "solid-js/web";
import { AppRouter } from "./AppRouter";
import "./index.css";

render(() => <AppRouter />, document.getElementById("root") as HTMLElement);
