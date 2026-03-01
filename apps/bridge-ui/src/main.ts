import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
import VisualScenarios from './visual/VisualScenarios.svelte'

const RootComponent = window.location.pathname.startsWith('/__visual__') ? VisualScenarios : App

const app = mount(RootComponent, {
  target: document.getElementById('app')!,
})

export default app
