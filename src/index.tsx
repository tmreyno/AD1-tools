/* @refresh reload */
import { render } from "solid-js/web";
import { AppRouter } from "./AppRouter";

render(() => <AppRouter />, document.getElementById("root") as HTMLElement);
