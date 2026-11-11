"use strict";
// New-password fields (templates/_pw_fields.html): Generate fills both with a random password from the browser's
// crypto.getRandomValues, Show toggles them visible, Copy puts the password on the clipboard. Nothing is sent
// anywhere until the form is submitted. A static file because the CSP allows no inline scripts.

const PW_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_+=!?#%";   // no 0/O, 1/l/I
const PW_LENGTH = 20;

function randomPassword() {
  // rejection sampling: only bytes below the largest multiple of the alphabet size, so every character is equally likely
  const limit = 256 - (256 % PW_CHARS.length);
  let out = "";
  while (out.length < PW_LENGTH) {
    for (const b of crypto.getRandomValues(new Uint8Array(PW_LENGTH * 2))) {
      if (b < limit && out.length < PW_LENGTH) out += PW_CHARS[b % PW_CHARS.length];
    }
  }
  return out;
}

for (const box of document.querySelectorAll("[data-pw]")) {
  const inputs = [...box.querySelectorAll("[data-pw-input]")];
  const toggle = box.querySelector("[data-pw-toggle]");
  const status = box.querySelector("[data-pw-status]");
  const say = (text) => { if (status) status.textContent = text; };
  const show = (on) => {
    for (const i of inputs) i.type = on ? "text" : "password";
    toggle.textContent = on ? "Hide" : "Show";
    toggle.setAttribute("aria-pressed", String(on));
  };
  box.querySelector("[data-pw-generate]")?.addEventListener("click", () => {
    const pw = randomPassword();
    for (const i of inputs) i.value = pw;
    say("Generated: copy it and hand it over.");
  });
  toggle?.addEventListener("click", () => show(inputs[0].type === "password"));
  box.querySelector("[data-pw-copy]")?.addEventListener("click", async () => {
    if (!inputs[0].value) { say("Nothing to copy yet."); return; }
    try {
      await navigator.clipboard.writeText(inputs[0].value);
      say("Copied.");
    } catch (e) {
      show(true);   // no clipboard access (plain HTTP, permissions): show it to copy by hand
      inputs[0].select();
      say("Copy it by hand (Ctrl+C).");
    }
  });
}
