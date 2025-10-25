// Simple functional medicine inventory using localStorage
    const STORAGE_KEY = 'med-inventory-v1';
    let medicines = [];
    let editingId = null;

    // sample data to start
    const sample = [
      {id: genId(), name: 'Paracetamol', strength:'500mg', category:'Analgesic', supplier:'PharmaCorp', quantity:150, unit:'tablets', batch:'PARA-2024-001', expiry:'2025-12-31'},
      {id: genId(), name: 'Amoxicillin', strength:'250mg', category:'Antibiotic', supplier:'MediSupply', quantity:30, unit:'capsules', batch:'AMOX-2024-002', expiry:'2025-03-15'},
      {id: genId(), name: 'Ibuprofen', strength:'400mg', category:'Anti-inflammatory', supplier:'PharmaCorp', quantity:200, unit:'tablets', batch:'IBU-2024-003', expiry:'2025-01-20'},
    ];

    function genId(){return 'id_'+Math.random().toString(36).slice(2,9)}

    function save(){localStorage.setItem(STORAGE_KEY, JSON.stringify(medicines));}
    function load(){
      const raw = localStorage.getItem(STORAGE_KEY);
      if(!raw){medicines = sample; save();} else medicines = JSON.parse(raw);
    }

    function daysBetween(dateA, dateB){
      const ms = 24*60*60*1000;
      return Math.round((dateA - dateB)/ms);
    }

    function statusFor(expiryStr, qty){
      const today = new Date();
      const exp = new Date(expiryStr+'T00:00:00');
      const days = daysBetween(exp, today);
      if(days < 0) return {cls:'expired', text:'EXPIRED'};
      if(days <= 90) return {cls:'expires-soon', text:`EXPIRES IN ${days} DAYS`};
      if(qty <= 30) return {cls:'ok', text:'LOW STOCK'};
      return {cls:'ok', text:'OK'};
    }

    function render(){
      const tbody = document.getElementById('tbody'); tbody.innerHTML='';
      const search = document.getElementById('search').value.trim().toLowerCase();
      let expCount=0, lowStock=0;
      medicines.forEach(m=>{
        const matches = !search || [m.name,m.category,m.batch,m.supplier,m.strength].join(' ').toLowerCase().includes(search);
        if(!matches) return;
        const tr = document.createElement('tr');
        const st = statusFor(m.expiry, m.quantity);
        if(st.cls==='expired') expCount++;
        if(m.quantity<=30) lowStock++;

        tr.innerHTML = `
          <td>
            <div class="row-title">${escapeHtml(m.name)} <div style="font-weight:600;font-size:13px;color:#a33">${escapeHtml(m.strength)}</div></div>
            <div class="muted">${escapeHtml(m.supplier)}</div>
          </td>
          <td>${escapeHtml(m.category)}</td>
          <td><div style="font-weight:700">${m.quantity} <span class="small">${escapeHtml(m.unit)}</span></div>${m.quantity<=30? '<div class="lowstock">LOW STOCK</div>':''}</td>
          <td>${escapeHtml(m.batch)}</td>
          <td>${escapeHtml(m.expiry)}</td>
          <td><span class="badge ${st.cls==='expired'? 'expired': (st.cls==='expires-soon'?'expires-soon':'ok')}">${st.text}</span></td>
          <td class="actions"><button data-id="${m.id}" class="editBtn">✎ Edit</button></td>
        `;
        tbody.appendChild(tr);
      });
      document.getElementById('expiringCount').textContent = expCount;
      document.getElementById('lowStockCount').textContent = lowStock;
      attachEditHandlers();
    }
    // edit button
    function attachEditHandlers(){
      document.querySelectorAll('.editBtn').forEach(b=>{
        b.onclick = ()=>{
          const id = b.dataset.id; openModalFor(id);
        }
      })
    }
    //open modal for edit 
    function openModalFor(id){
      editingId = id || null;
      document.getElementById('modalTitle').textContent = id? 'Edit medicine' : 'Add medicine';
      if(id){
        const m = medicines.find(x=>x.id===id);
        document.getElementById('mName').value = m.name;
        document.getElementById('mStrength').value = m.strength || '';
        document.getElementById('mCategory').value = m.category || '';
        document.getElementById('mSupplier').value = m.supplier || '';
        document.getElementById('mQuantity').value = m.quantity;
        document.getElementById('mUnit').value = m.unit || '';
        document.getElementById('mBatch').value = m.batch || '';
        document.getElementById('mExpiry').value = m.expiry || '';
      } else {
        document.getElementById('mName').value = '';
        document.getElementById('mStrength').value = '';
        document.getElementById('mCategory').value = '';
        document.getElementById('mSupplier').value = '';
        document.getElementById('mQuantity').value = 0;
        document.getElementById('mUnit').value = '';
        document.getElementById('mBatch').value = '';
        document.getElementById('mExpiry').value = '';
      }
      document.getElementById('modal').classList.add('open');
    }
    // closemodal
    function closeModal(){document.getElementById('modal').classList.remove('open'); editingId=null}

    document.getElementById('openAdd').addEventListener('click', ()=>openModalFor());
    document.getElementById('cancelBtn').addEventListener('click', closeModal);
    document.getElementById('search').addEventListener('input', ()=>render());
    
    // save button
    document.getElementById('saveBtn').addEventListener('click', ()=>{
      const name = document.getElementById('mName').value.trim();
      const strength = document.getElementById('mStrength').value.trim();
      const category = document.getElementById('mCategory').value.trim();
      const supplier = document.getElementById('mSupplier').value.trim();
      const quantity = parseInt(document.getElementById('mQuantity').value||0,10);
      const unit = document.getElementById('mUnit').value.trim();
      const batch = document.getElementById('mBatch').value.trim();
      const expiry = document.getElementById('mExpiry').value;
      if(!name || !expiry){alert('Please provide at least name and expiration date.'); return}
      if(editingId){
        const m = medicines.find(x=>x.id===editingId);
        Object.assign(m,{name, strength, category, supplier, quantity, unit, batch, expiry});
      } else {
        medicines.unshift({id:genId(), name, strength, category, supplier, quantity, unit, batch, expiry});
      }
      save(); render(); closeModal();
    });

    // small utility
    function escapeHtml(s){return String(s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}

    // init
    load(); render();

    // keyboard: esc to close modal
    document.addEventListener('keydown', e=>{if(e.key==='Escape') closeModal();});

    // expose a simple reset helper for dev (type resetInventory() in console)x
    window.resetInventory = ()=>{if(confirm('Reset inventory to sample data?')){medicines = sample; save(); render();}}
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