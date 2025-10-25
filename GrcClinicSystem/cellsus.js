// CELLSUS page features
document.addEventListener('DOMContentLoaded', () => {
  const nameInput = document.getElementById('nameInput');
  const courseInput = document.getElementById('courseInput');
  const idInput = document.getElementById('idInput');
  const complaintInput = document.getElementById('complaintInput');
  const medicineInput = document.getElementById('medicineInput');
  const addBtn = document.getElementById('addPatientBtn');
  const tableBody = document.getElementById('patientTableBody');

  // Load from localStorage
  function loadPatients() {
    const patients = JSON.parse(localStorage.getItem('patients')) || [];
    tableBody.innerHTML = '';

    // Show newest first
    patients.forEach(patient => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${patient.date}</td>
        <td>${patient.name}</td>
        <td>${patient.course}</td>
        <td>${patient.id}</td>
        <td>${patient.complaint}</td>
        <td>${patient.medicine}</td>
      `;
      tableBody.appendChild(row);
    });
  }

  // Add new patient
  if (addBtn) {
    addBtn.addEventListener('click', () => {
      const name = nameInput.value.trim();
      const course = courseInput.value.trim();
      const id = idInput.value.trim();
      const complaint = complaintInput.value.trim();
      const medicine = medicineInput.value.trim();

      if (!name || !course || !id || !complaint || !medicine) {
        alert("Please fill out all fields.");
        return;
      }

      const now = new Date();
      const newPatient = {
        date: now.toLocaleString(),       // readable date for table
        createdAt: now.toISOString(),     // precise date for dashboard logic
        name,
        course,
        id,
        complaint,
        medicine
      };

      const patients = JSON.parse(localStorage.getItem('patients')) || [];
      patients.unshift(newPatient); // newest first
      localStorage.setItem('patients', JSON.stringify(patients));

       // ✅ ADDITION: Save complaint separately for Statistic Chart
      let complaints = JSON.parse(localStorage.getItem('complaintsData')) || [];
      complaints.push(complaint);
      localStorage.setItem('complaintsData', JSON.stringify(complaints));
      // ✅ END ADDITION

      // Clear form
      nameInput.value = '';
      courseInput.value = '';
      idInput.value = '';
      complaintInput.value = '';
      medicineInput.value = '';

      loadPatients();
    });
  }

  // Load table when page opens
  if (tableBody) loadPatients();
});
const hamburger = document.getElementById('hamburger');
  const sidebar = document.querySelector('.sidebar');

  hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    sidebar.classList.toggle('show');
  });
  
  // ---------------------------
// ✅ AUTO DEDUCT FROM INVENTORY WHEN CELLSUS ADDS MEDICINE
// ---------------------------
(function() {
  const addBtn = document.getElementById('addPatientBtn');
  if (!addBtn) return;

  addBtn.addEventListener('click', () => {
    const medName = document.getElementById('medicineInput').value.trim();
    if (!medName) return; // skip if empty

    // small delay to let patient save finish
    setTimeout(() => {
      try {
        const raw = localStorage.getItem('med-inventory-v1');
        if (!raw) return;
        const meds = JSON.parse(raw);

        const med = meds.find(m => m.name.toLowerCase() === medName.toLowerCase());
        if (!med) {
          console.warn(`Medicine "${medName}" not found in inventory.`);
          return;
        }

        if (med.quantity > 0) {
          med.quantity -= 1; // default bawas = 1
          localStorage.setItem('med-inventory-v1', JSON.stringify(meds));
          console.log(`✅ ${medName} stock deducted by 1. Remaining: ${med.quantity}`);
        } else {
          alert(`⚠️ ${med.name} is out of stock!`);
        }
      } catch (e) {
        console.error('Inventory update failed:', e);
      }
    }, 100); // 100ms delay ensures save is done before deduction
  });
})();

/// ======================================
// ✅ ENHANCEMENT: Search bar beside "Add Patient" + Scrollable Table
// ======================================
document.addEventListener("DOMContentLoaded", () => { 
  const addBtn = document.getElementById("addPatientBtn");
  const tableBody = document.getElementById("patientTableBody");
  if (!addBtn || !tableBody) return;

  // 🔍 Create search input element
  const searchInput = document.createElement("input");
  searchInput.type = "text";
  searchInput.placeholder = "🔍 Search";
  searchInput.id = "patientSearch";
  searchInput.style.marginLeft = "10px";
  searchInput.style.padding = "8px 10px";
  searchInput.style.border = "1px solid #ccc";
  searchInput.style.borderRadius = "6px";
  searchInput.style.maxWidth = "240px";

  // 🧩 Place search bar beside the Add Patient button
  addBtn.parentElement?.insertBefore(searchInput, addBtn.nextSibling);

  // 🔄 Filter and render
  function renderFilteredPatients(searchTerm = "") {
    const patients = JSON.parse(localStorage.getItem("patients")) || [];
    const filtered = patients.filter((p) => {
      const term = searchTerm.toLowerCase();
      return (
        (p.name && p.name.toLowerCase().includes(term)) ||
        (p.id && p.id.toString().toLowerCase().includes(term))
      );
    });

    tableBody.innerHTML = "";

    if (filtered.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center;color:#888;">No matching records found.</td>
        </tr>`;
      return;
    }

    filtered.forEach((patient) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${patient.date}</td>
        <td>${patient.name}</td>
        <td>${patient.course}</td>
        <td>${patient.id}</td>
        <td>${patient.complaint}</td>
        <td>${patient.medicine}</td>
      `;
      tableBody.appendChild(row);
    });
  }

  // 🧠 Listen to search input
  searchInput.addEventListener("input", (e) => {
    renderFilteredPatients(e.target.value);
  });
});

  document.querySelector(".logout-btn").addEventListener("click", () => {
  localStorage.removeItem("loggedInUser");
  sessionStorage.removeItem("loggedInUser");
  window.location.href = "login.html";
});