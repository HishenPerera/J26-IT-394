/**
 * ============================================================
 *  XSS VULNERABILITY EXAMPLES — Sentinel Test File
 *  Rule: SENTINEL-XSS-001 | Language: TypeScript / JavaScript
 * ============================================================
 *
 *  Open this file in VS Code with the Sentinel extension active.
 *  Every marked line below will be underlined with a diagnostic.
 * ============================================================
 */

// ── 1. innerHTML with user-controlled variable ───────────────────────────────
//  The most common XSS vector. Attacker supplies: <img src=x onerror=alert(1)>

function renderUserProfile(userBio: string) {
  const div = document.getElementById("profile");
  div!.innerHTML = userBio;                    // ❌ SENTINEL-XSS-001 detected here
}

// ── 2. outerHTML with variable ───────────────────────────────────────────────
//  Replaces the entire element — even more destructive than innerHTML.

function replaceWidget(newHtml: string) {
  const widget = document.querySelector(".widget");
  (widget as HTMLElement).outerHTML = newHtml; // ❌ SENTINEL-XSS-001 detected here
}

// ── 3. document.write with variable ─────────────────────────────────────────
//  Executes immediately during page load; any script tags in `content` run.

function loadLegacyContent(content: string) {
  document.write(content);                     // ❌ SENTINEL-XSS-001 detected here
}

// ── 4. eval() with variable input ───────────────────────────────────────────
//  Highest severity — arbitrary code execution, not just HTML injection.

function runUserScript(code: string) {
  eval(code);                                  // ❌ SENTINEL-XSS-001 detected here (95% confidence)
}

// ── 5. setTimeout with string argument ──────────────────────────────────────
//  String-form setTimeout behaves like eval().

function scheduleAction(userAction: string, delay: number) {
  setTimeout(userAction, delay);               // ❌ SENTINEL-XSS-001 detected here
}

// ── 6. setInterval with string argument ─────────────────────────────────────

function pollAction(userCode: string) {
  setInterval(userCode, 1000);                 // ❌ SENTINEL-XSS-001 detected here
}

// ── 7. React dangerouslySetInnerHTML ────────────────────────────────────────
//  React's escape hatch — if the HTML is not sanitized, XSS is trivial.

import React from "react";

function CommentBox({ rawHtml }: { rawHtml: string }) {
  return (
    <div
      dangerouslySetInnerHTML={{ __html: rawHtml }}   // ❌ SENTINEL-XSS-001 detected here
    />
  );
}

// ── 8. jQuery .html() with variable ─────────────────────────────────────────
//  Equivalent to innerHTML — jQuery does not sanitize the argument.

declare const $: any;

function updatePanel(serverResponse: string) {
  $("#panel").html(serverResponse);            // ❌ SENTINEL-XSS-001 detected here
}

// ── ✅ SAFE equivalents (Sentinel will NOT flag these) ───────────────────────

function safeRender(userInput: string) {
  const div = document.getElementById("safe");

  // ✅ textContent — plain text only, no HTML parsing
  div!.textContent = userInput;

  // ✅ Static HTML literal — no variable involved
  div!.innerHTML = "<strong>Hello</strong>";

  // ✅ Sanitised with DOMPurify before assignment
  // import DOMPurify from "dompurify";
  // div!.innerHTML = DOMPurify.sanitize(userInput);
}
