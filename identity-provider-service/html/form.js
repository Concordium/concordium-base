"use strict";

(() => {
  const form = document.querySelector("form");
  const submit = document.querySelector("#submit");
  const company = Boolean(form.elements.legalName);
  const expiry = form.elements.expiry;
  const expiryYear = document.querySelector("#expiry-year");
  const expiryMonth = document.querySelector("#expiry-month");
  const now = new Date();
  for (let year = now.getFullYear(); year <= now.getFullYear() + 20; year++) {
    expiryYear.add(new Option(String(year), String(year)));
  }
  expiryYear.value = String(now.getFullYear() + 10);
  expiryMonth.value = String(now.getMonth() + 1).padStart(2, "0");
  function syncExpiry() {
    expiry.value =
      expiryYear.value && expiryMonth.value
        ? `${expiryYear.value}-${expiryMonth.value}`
        : "";
  }
  syncExpiry();
  expiry.required = false;
  expiry.type = "hidden";
  document.querySelector("#expiry-fallback").hidden = true;
  document.querySelector("#expiry-pickers").hidden = false;
  expiryYear.required = expiryMonth.required = true;
  for (const select of [expiryYear, expiryMonth]) {
    select.addEventListener("input", syncExpiry);
  }

  form.querySelectorAll("[data-date]").forEach((control) => {
    control.type = "date";
    control.removeAttribute("pattern");
    control.removeAttribute("inputmode");
    control.removeAttribute("placeholder");
  });
  // Date inputs use ISO dates in the UI; the service expects YYYYMMDD.
  form.addEventListener("formdata", (event) => {
    syncExpiry();
    event.formData.set("expiry", expiry.value);
    form.querySelectorAll("[data-date]").forEach((control) => {
      event.formData.set(control.name, control.value.replaceAll("-", ""));
    });
    if (company) {
      for (const name of [
        "legalName",
        "businessNumber",
        "lei",
        "registrationAuth",
      ]) {
        const value = form.elements[name].value.trim();
        event.formData.set(name, name === "lei" ? value.toUpperCase() : value);
      }
    }
  });

  // Add inline errors to fields that use native validity checks.
  form
    .querySelectorAll(
      'input:not([type="hidden"]):not([type="checkbox"]),select',
    )
    .forEach((control) => {
      let error = document.getElementById(`${control.id}-error`);
      if (!error) {
        error = document.createElement("p");
        error.id = `${control.id}-error`;
        error.className = "error";
        error.hidden = true;
        control.closest(".field").append(error);
      }
      const descriptions = new Set(
        (control.getAttribute("aria-describedby") || "")
          .split(" ")
          .filter(Boolean),
      );
      descriptions.add(error.id);
      control.setAttribute("aria-describedby", [...descriptions].join(" "));
    });

  function validateCompany() {
    if (!company) return;
    const name = form.elements.legalName;
    const business = form.elements.businessNumber;
    const lei = form.elements.lei;
    name.setCustomValidity(name.value.trim() ? "" : "Enter the legal name.");
    business.setCustomValidity(
      business.value.trim() || lei.value.trim()
        ? ""
        : "Enter a business number or an LEI.",
    );
    const value = lei.value.trim().toUpperCase();
    let valid = !value;
    if (/^[A-Z0-9]{4}00[A-Z0-9]{12}[0-9]{2}$/.test(value)) {
      let remainder = 0;
      for (const char of value) {
        const digits = /[A-Z]/.test(char)
          ? String(char.charCodeAt(0) - 55)
          : char;
        for (const digit of digits)
          remainder = (remainder * 10 + Number(digit)) % 97;
      }
      valid = remainder === 1;
    }
    lei.setCustomValidity(valid ? "" : "Enter a valid LEI.");
  }
  function showError(control) {
    const error = document.getElementById(`${control.id}-error`);
    if (!error) return;
    control.setAttribute("aria-invalid", String(!control.validity.valid));
    error.hidden = control.validity.valid;
    error.textContent = control.validity.valid ? "" : control.validationMessage;
  }
  function normalizeCompany() {
    if (!company) return;
    for (const name of [
      "legalName",
      "businessNumber",
      "lei",
      "registrationAuth",
    ]) {
      form.elements[name].value = form.elements[name].value.trim();
    }
    form.elements.lei.value = form.elements.lei.value.toUpperCase();
  }
  form.addEventListener("input", () => {
    validateCompany();
    form.querySelectorAll("[aria-invalid]").forEach(showError);
  });
  form.addEventListener("focusout", (event) => {
    if (
      event.target.matches(
        'input:not([type="hidden"]):not([type="checkbox"]),select',
      )
    ) {
      normalizeCompany();
      validateCompany();
      showError(event.target);
    }
  });

  const pick = (values) => values[Math.floor(Math.random() * values.length)];
  const digits = () => String(Math.floor(Math.random() * 900000) + 100000);
  function randomLei() {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const characters = (length) =>
      Array.from({ length }, () => pick(alphabet)).join("");
    const base = `${characters(4)}00${characters(12)}`;
    let remainder = 0;
    for (const char of `${base}00`) {
      const numbers = /[A-Z]/.test(char)
        ? String(char.charCodeAt(0) - 55)
        : char;
      for (const digit of numbers)
        remainder = (remainder * 10 + Number(digit)) % 97;
    }
    return `${base}${String(98 - remainder).padStart(2, "0")}`;
  }
  document.querySelector("#randomize").addEventListener("click", () => {
    const year = new Date().getFullYear();
    const month = String(Math.floor(Math.random() * 12) + 1).padStart(2, "0");
    const day = String(Math.floor(Math.random() * 28) + 1).padStart(2, "0");
    const country = pick([
      "DK",
      "DE",
      "SE",
      "NO",
      "FI",
      "NL",
      "FR",
      "GB",
      "CA",
      "AU",
    ]);
    const suffix = digits();
    const values = company
      ? {
          legalName: `${pick(["Fjordhaven", "Birchmere", "Skovdal", "Alderwick"])} Test ${pick(["Trading", "Logistics", "Research", "Manufacturing"])} ${suffix}`,
          legalCountry: country,
          businessNumber: `TEST-BIZ-${suffix}`,
          lei: randomLei(),
          registrationAuth: `Fictional Test Registry ${suffix}`,
        }
      : {
          firstName: pick(["Mira", "Anika", "Soren", "Elin", "Ravi", "Leona"]),
          lastName: pick([
            "Lindholm",
            "Berglund",
            "Vestergaard",
            "Nygaard",
            "Solberg",
            "Aalto",
          ]),
          sex: pick(["0", "1", "2", "9"]),
          dob: `${year - 20 - Math.floor(Math.random() * 50)}-${month}-${day}`,
          countryOfResidence: country,
          nationality: country,
          idDocType: pick(["1", "2", "3", "4"]),
          idDocNo: `TEST-DOC-${suffix}`,
          idDocIssuer: country,
          idDocIssuedAt: `${year - 2}-${month}-${day}`,
          idDocExpiresAt: `${year + 5}-${month}-${day}`,
          nationalIdNo: `TEST-N-${digits()}`,
          taxIdNo: `TEST-T-${digits()}`,
        };
    for (const [name, value] of Object.entries(values))
      form.elements[name].value = value;
    validateCompany();
    form.querySelectorAll("[aria-invalid]").forEach(showError);
  });
  document.querySelector(".attribute-tools").hidden = false;

  // Keep native POST/redirect behavior. Only invalid submissions are stopped here.
  form.addEventListener("submit", (event) => {
    syncExpiry();
    normalizeCompany();
    validateCompany();
    const controls = [...form.querySelectorAll("input,select")];
    controls.forEach(showError);
    const invalid = controls.find((control) => !control.validity.valid);
    if (invalid) {
      event.preventDefault();
      const disclosure = invalid.closest("details");
      if (disclosure) disclosure.open = true;
      invalid.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Submitting…";
  });
  window.addEventListener("pageshow", () => {
    submit.disabled = false;
    submit.textContent = "Create test identity";
  });
  document.querySelector(".layout").classList.add("enter");
  // Native constraints remain available when JavaScript is disabled.
  form.noValidate = true;
})();
