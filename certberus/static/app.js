/**
 * Certberus Web Console - Core Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    const API_BASE = '/_certberus/admin';
    const state = {
        activeView: 'dashboard',
        token: localStorage.getItem('certberus_token') || '',
        certificates: [],
        stats: { total_active: 0, total_revoked: 0, total: 0 }
    };

    // UI Elements
    const mainApp = document.getElementById('main-app');
    const loginScreen = document.getElementById('login-screen');
    const tokenInput = document.getElementById('admin-token-input');
    const loginSubmit = document.getElementById('login-submit');
    const loginError = document.getElementById('login-error');
    
    const navItems = document.querySelectorAll('nav li');
    const viewTitle = document.getElementById('view-title');
    const contentArea = document.getElementById('content-area');
    const refreshBtn = document.getElementById('refresh-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const revokeModal = document.getElementById('revoke-modal');
    
    let selectedSerial = null;

    // Initialization
    function init() {
        if (state.token) {
            checkAuthAndLoad();
        } else {
            showLogin();
        }
        setupEventListeners();
    }

    function showLogin() {
        mainApp.style.display = 'none';
        loginScreen.style.display = 'flex';
        tokenInput.focus();
    }

    function hideLogin() {
        loginScreen.style.display = 'none';
        mainApp.style.display = 'flex';
    }

    async function checkAuthAndLoad() {
        // Simple health check to verify token
        const stats = await apiRequest('/stats');
        if (stats) {
            hideLogin();
            loadCurrentView();
        } else {
            showLogin();
            if (state.token) {
                loginError.innerText = 'Token inválido o expirado.';
            }
        }
    }

    async function apiRequest(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const defaultOptions = {
            headers: {
                'X-Certberus-Token': state.token,
                'Content-Type': 'application/json'
            }
        };

        try {
            const response = await fetch(url, { ...defaultOptions, ...options });
            if (response.status === 403) {
                return null;
            }
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            return await response.json();
        } catch (err) {
            console.error(err);
            return null;
        }
    }

    // View Loading
    async function loadCurrentView() {
        contentArea.classList.remove('content-fade');
        void contentArea.offsetWidth; // Trigger reflow
        contentArea.classList.add('content-fade');

        if (state.activeView === 'dashboard') {
            await renderDashboard();
        } else if (state.activeView === 'certificates') {
            await renderCertificates();
        } else if (state.activeView === 'config') {
            await renderConfig();
        }
    }

    async function renderDashboard() {
        viewTitle.innerText = 'Dashboard';
        const stats = await apiRequest('/stats');
        if (!stats) return;
        
        state.stats = stats;
        
        contentArea.innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon blue"><i class="fas fa-certificate"></i></div>
                    <div class="stat-info">
                        <h3>Total Certificados</h3>
                        <div class="stat-value">${stats.total}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon green"><i class="fas fa-shield-check"></i></div>
                    <div class="stat-info">
                        <h3>Activos</h3>
                        <div class="stat-value">${stats.total_active}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon red"><i class="fas fa-ban"></i></div>
                    <div class="stat-info">
                        <h3>Revocados</h3>
                        <div class="stat-value">${stats.total_revoked}</div>
                    </div>
                </div>
            </div>
            
            <div class="recent-actions-section">
                <h2 style="margin-bottom: 1.5rem;">Estado de la Infraestructura</h2>
                <div class="status-card" style="background: var(--glass-bg); padding: 2rem; border-radius: 24px; border: 1px solid var(--glass-border);">
                     <div style="display: flex; align-items: center; gap: 20px;">
                        <div class="dot online" style="width: 12px; height: 12px;"></div>
                        <div>
                            <h4 style="margin-bottom: 4px;">PKI Core Engine</h4>
                            <p style="color: var(--text-secondary); font-size: 0.9rem;">Operando normalmente bajo políticas de Seguridad</p>
                        </div>
                     </div>
                </div>
            </div>
        `;
    }

    async function renderCertificates() {
        viewTitle.innerText = 'Certificados';
        const certs = await apiRequest('/certificates');
        if (!certs) return;
        
        state.certificates = certs;

        const tableRows = certs.map(cert => `
            <tr>
                <td style="font-weight: 500;">${cert.common_name}</td>
                <td style="font-family: monospace; color: var(--accent-primary);">${cert.serial_number.substring(0, 12)}...</td>
                <td>${new Date(cert.issued_at).toLocaleDateString()}</td>
                <td><span class="status-badge ${cert.revoked_at ? 'revoked' : 'active'}">${cert.revoked_at ? 'Revocado' : 'Activo'}</span></td>
                <td>
                    ${!cert.revoked_at ? `<button class="action-btn" onclick="openRevokeModal('${cert.serial_number}')"><i class="fas fa-ban"></i> Revocar</button>` : '<span style="color: var(--text-secondary); font-size: 0.8rem;">---</span>'}
                </td>
            </tr>
        `).join('');

        contentArea.innerHTML = `
            <div class="data-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Nombre Común (CN)</th>
                            <th>Nº Serie</th>
                            <th>Fecha Emisión</th>
                            <th>Estado</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows.length ? tableRows : '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No hay certificados registrados.</td></tr>'}
                    </tbody>
                </table>
            </div>
        `;
    }

    async function renderConfig() {
        viewTitle.innerText = 'Configuración';
        const config = await apiRequest('/config');
        if (!config) return;

        contentArea.innerHTML = `
            <div class="config-grid" style="display: grid; gap: 1.5rem;">
                <div class="config-card" style="background: var(--glass-bg); padding: 2rem; border-radius: 24px; border: 1px solid var(--glass-border);">
                    <h3>Políticas de Seguridad (Software Filter)</h3>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1.5rem;">Restringe qué dominios e IPs puede firmar Certberus mediante reglas de software.</p>
                    <div style="margin-top: 1.5rem; display: grid; gap: 20px;">
                        <div>
                            <label style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 8px; display: block;">Dominios Permitidos (uno por línea)</label>
                            <textarea id="allowed-domains-input" class="config-input" rows="3">${config.security.allowed_domains.join('\n')}</textarea>
                        </div>
                        <div>
                            <label style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 8px; display: block;">IPs / Redes Permitidas (uno por línea)</label>
                            <textarea id="allowed-ips-input" class="config-input" rows="3">${config.security.allowed_ips.join('\n')}</textarea>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="font-size: 0.85rem; color: var(--warning);">
                                <i class="fas fa-info-circle"></i> Las "Name Constraints" criptográficas requieren reiniciar la CA.
                            </div>
                            <button onclick="saveSecurityPolicy()" class="btn-primary btn-small">Guardar Cambios</button>
                        </div>
                    </div>
                </div>

                <div class="config-card" style="background: var(--glass-bg); padding: 2rem; border-radius: 24px; border: 1px solid var(--glass-border);">
                    <h3>Endpoints Activos</h3>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1.5rem;">Controla qué funciones de la API están disponibles públicamente.</p>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                        ${Object.entries(config.endpoints).map(([key, enabled]) => `
                            <div style="background: rgba(255,255,255,0.03); padding: 15px; border-radius: 16px; border: 1px solid var(--glass-border); display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <span style="font-size: 0.95rem; display: block; text-transform: capitalize;">${key.replace(/_/g, ' ')}</span>
                                    <span style="font-size: 0.75rem; color: var(--text-secondary);">${enabled ? 'Habilitado' : 'Desactivado'}</span>
                                </div>
                                <label class="switch">
                                    <input type="checkbox" ${enabled ? 'checked' : ''} onchange="toggleEndpoint('${key}', this.checked)">
                                    <span class="slider"></span>
                                </label>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    window.toggleEndpoint = async (endpoint, enabled) => {
        const loadingBadge = document.createElement('span');
        loadingBadge.className = 'badge';
        loadingBadge.innerText = 'Actualizando...';
        loadingBadge.style.marginLeft = '10px';
        viewTitle.appendChild(loadingBadge);

        const patch = {
            endpoints: {
                [endpoint]: enabled
            }
        };

        const res = await apiRequest('/config', {
            method: 'PATCH',
            body: JSON.stringify(patch)
        });

        loadingBadge.remove();

        if (res) {
            // Success - refresh the view to show updated text
            renderConfig();
        } else {
            alert('Error al actualizar la configuración. Verifica tu conexión o token.');
            renderConfig(); // Reset UI
        }
    };

    window.saveSecurityPolicy = async () => {
        const domains = document.getElementById('allowed-domains-input').value.split('\n').map(d => d.trim()).filter(d => d);
        const ips = document.getElementById('allowed-ips-input').value.split('\n').map(ip => ip.trim()).filter(ip => ip);

        const patch = {
            security: {
                allowed_domains: domains,
                allowed_ips: ips
            }
        };

        const res = await apiRequest('/config', {
            method: 'PATCH',
            body: JSON.stringify(patch)
        });

        if (res) {
            alert('Política de seguridad actualizada correctamente.');
            renderConfig();
        } else {
            alert('Error al guardar la política de seguridad.');
        }
    };

    // Event Helpers
    window.openRevokeModal = (serial) => {
        selectedSerial = serial;
        revokeModal.style.display = 'block';
    };

    function setupEventListeners() {
        loginSubmit.onclick = async () => {
            const token = tokenInput.value.trim();
            if (!token) return;
            
            state.token = token;
            const stats = await apiRequest('/stats');
            if (stats) {
                localStorage.setItem('certberus_token', token);
                hideLogin();
                loadCurrentView();
            } else {
                loginError.innerText = 'Token inválido.';
                state.token = '';
            }
        };

        tokenInput.onkeypress = (e) => {
            if (e.key === 'Enter') loginSubmit.click();
        };

        navItems.forEach(item => {
            item.onclick = () => {
                navItems.forEach(n => n.classList.remove('active'));
                item.classList.add('active');
                state.activeView = item.dataset.view;
                loadCurrentView();
            };
        });

        refreshBtn.onclick = loadCurrentView;

        logoutBtn.onclick = () => {
            localStorage.removeItem('certberus_token');
            state.token = '';
            showLogin();
        };

        document.getElementById('cancel-revoke').onclick = () => {
            revokeModal.style.display = 'none';
        };

        document.getElementById('confirm-revoke').onclick = async () => {
            const reason = document.getElementById('revoke-reason').value;
            const res = await apiRequest(`/certificates/${selectedSerial}/revoke`, {
                method: 'POST',
                body: JSON.stringify({ reason })
            });
            
            if (res) {
                revokeModal.style.display = 'none';
                loadCurrentView();
            }
        };

        // Close modal when clicking outside
        window.onclick = (event) => {
            if (event.target == revokeModal) {
                revokeModal.style.display = 'none';
            }
        };
    }

    init();
});
