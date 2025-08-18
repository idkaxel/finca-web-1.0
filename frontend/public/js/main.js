document.getElementById('activityForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    
    try {
      const response = await fetch('/register-activity', {
        method: 'POST',
        body: formData
      });
      
      if (response.ok) {
        window.location.reload();
      } else {
        alert('Error al registrar actividad');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  });
  
  // Cargar historial
  async function loadActivities() {
    const response = await fetch('/activities');
    const activities = await response.json();
    
    const container = document.getElementById('activities');
    container.innerHTML = activities.map(activity => `
      <div class="activity-item">
        <h3>${activity.activityType} - ${new Date(activity.date).toLocaleString()}</h3>
        <p><strong>Motivo:</strong> ${activity.reason}</p>
        <p><strong>Prueba:</strong> ${activity.proof.startsWith('http') ? 
          `<a href="${activity.proof}" target="_blank">Enlace</a>` : 
          `<a href="/uploads/${activity.proof}" target="_blank">Ver archivo</a>`}
        </p>
      </div>
    `).join('');
  }
  
  loadActivities();  