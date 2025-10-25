document.addEventListener("DOMContentLoaded", () => {
  const nameInput = document.getElementById("schedName");
  const idInput = document.getElementById("schedId");
  const dateInput = document.getElementById("schedDate");
  const timeInput = document.getElementById("schedTime");
  const notesInput = document.getElementById("schedNotes");
  const addBtn = document.getElementById("addScheduleBtn");
  const tableBody = document.getElementById("scheduleTableBody");

  // Toast container
  const toastContainer = document.createElement("div");
  toastContainer.style.position = "fixed";
  toastContainer.style.top = "20px";
  toastContainer.style.right = "20px";
  toastContainer.style.zIndex = "9999";
  document.body.appendChild(toastContainer);

  // Load schedules
  let schedules = JSON.parse(localStorage.getItem("schedules")) || [];

  function saveAndRender() {
    localStorage.setItem("schedules", JSON.stringify(schedules));
    renderSchedules();
  }

  function renderSchedules() {
    const now = new Date();

    // Sort by soonest date/time
    schedules.sort((a, b) => new Date(`${a.date}T${a.time}`) - new Date(`${b.date}T${b.time}`));

    tableBody.innerHTML = "";

    schedules.forEach((s, index) => {
      if (s.archived) return;

      const schedTime = new Date(`${s.date}T${s.time}`);
      const timeFormatted = schedTime.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true,
      });

      const diffMinutes = (schedTime - now) / 60000;

      // ✅ highlight if within next 1 hour
      let rowStyle = "";
      if (diffMinutes > 0 && diffMinutes <= 60) {
        rowStyle = "background-color: #fff3cd;"; // light yellow
      }

      const row = `
        <tr style="${rowStyle}">
          <td>${s.name}</td>
          <td>${s.id}</td>
          <td>${s.date}</td>
          <td>${timeFormatted}</td>
          <td>${s.notes}</td>
          <td>
            <button class="archiveBtn" data-index="${index}"
              style="background-color:#6b0000;color:white;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;">
              Archive
            </button>
          </td>
        </tr>
      `;
      tableBody.insertAdjacentHTML("beforeend", row);
    });
  }

  // ✅ Add new schedule
  addBtn.addEventListener("click", () => {
    const name = nameInput.value.trim();
    const id = idInput.value.trim();
    const date = dateInput.value;
    const time = timeInput.value;
    const notes = notesInput.value.trim();

    if (!name || !date || !time) {
      showToast("⚠️ Please fill in all required fields!", "warning");
      return;
    }

    schedules.push({ name, id, date, time, notes, archived: false });
    saveAndRender();

    // Clear inputs
    nameInput.value = "";
    idInput.value = "";
    dateInput.value = "";
    timeInput.value = "";
    notesInput.value = "";

    showToast("✅ Schedule added successfully!", "success");
  });

  // ✅ Archive schedule
  tableBody.addEventListener("click", (e) => {
    if (e.target.classList.contains("archiveBtn")) {
      const index = e.target.getAttribute("data-index");
      schedules[index].archived = true;
      saveAndRender();
      showToast("📦 Schedule archived!", "info");
    }
  });

  // ✅ Toast notification
  function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.textContent = message;
    toast.style.background =
      type === "success" ? "#28a745" :
      type === "warning" ? "#ffc107" :
      type === "info" ? "#007bff" :
      "#dc3545";
    toast.style.color = "white";
    toast.style.padding = "10px 15px";
    toast.style.marginTop = "10px";
    toast.style.borderRadius = "8px";
    toast.style.boxShadow = "0 2px 6px rgba(0,0,0,0.3)";
    toast.style.opacity = "1";
    toast.style.transition = "opacity 0.5s ease";
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 500);
    }, 3000);
  }

  // ✅ Check upcoming schedules (within 1 hour)
  function checkUpcomingSchedules() {
    const now = new Date();
    schedules.forEach((s) => {
      if (s.archived) return;
      const schedTime = new Date(`${s.date}T${s.time}`);
      const diff = schedTime - now;
      const minutes = diff / 6000;

      if (minutes > 0 && minutes <= 60) {
        showToast(`⏰ Reminder: ${s.name} has a schedule at ${schedTime.toLocaleTimeString([], {
          hour: "2-digit", minute: "2-digit", hour12: true
        })}`, "warning");
      }
    });
    renderSchedules(); // ✅ update highlights live
  }

  // Check every 1 minute
  setInterval(checkUpcomingSchedules, 60000);

  renderSchedules();
});
const hamburger = document.getElementById('hamburger');
  const sidebar = document.querySelector('.sidebar');

  hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    sidebar.classList.toggle('show');
  });

  document.querySelector(".logout-btn").addEventListener("click", () => {
  localStorage.removeItem("loggedInUser");
  sessionStorage.removeItem("loggedInUser");
  window.location.href = "login.html";
});