// Application State
const state = {
    categories: [],
    passwords: [],
    currentCategory: null,
    currentPassword: null,
    isAuthenticated: false
};

// DOM Elements
const elements = {
    setupScreen: document.getElementById('setup-screen'),
    loginScreen: document.getElementById('login-screen'),
    mainApp: document.getElementById('main-app'),
    setupForm: document.getElementById('setup-form'),
    loginForm: document.getElementById('login-form'),
    categoriesList: document.getElementById('categories-list'),
    passwordsList: document.getElementById('passwords-list'),
    emptyState: document.getElementById('empty-state'),
    passwordCount: document.getElementById('password-count'),
    currentCategoryTitle: document.getElementById('current-category'),
    searchInput: document.getElementById('search-input'),
    addPasswordBtn: document.getElementById('add-password-btn'),
    addCategoryBtn: document.getElementById('add-category-btn'),
    logoutBtn: document.getElementById('logout-btn'),
    passwordModal: document.getElementById('password-modal'),
    generatorModal: document.getElementById('generator-modal'),
    viewModal: document.getElementById('view-modal'),
    toast: document.getElementById('toast')
};

// Utility Functions
function showToast(message, type = 'success') {
    elements.toast.textContent = message;
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove('hidden');

    setTimeout(() => {
        elements.toast.classList.add('hidden');
    }, 3000);
}

async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }

        return data;
    } catch (error) {
        showToast(error.message, 'error');
        throw error;
    }
}

// Authentication
async function checkAuthStatus() {
    try {
        const status = await apiCall('/api/auth/status');

        if (!status.has_master_password) {
            showScreen('setup');
        } else if (!status.is_authenticated) {
            showScreen('login');
        } else {
            state.isAuthenticated = true;
            showScreen('main');
            await loadData();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

function showScreen(screen) {
    elements.setupScreen.classList.add('hidden');
    elements.loginScreen.classList.add('hidden');
    elements.mainApp.classList.add('hidden');

    switch (screen) {
        case 'setup':
            elements.setupScreen.classList.remove('hidden');
            break;
        case 'login':
            elements.loginScreen.classList.remove('hidden');
            break;
        case 'main':
            elements.mainApp.classList.remove('hidden');
            break;
    }
}

elements.setupForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-password-confirm').value;

    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    if (password.length < 8) {
        showToast('Password must be at least 8 characters', 'error');
        return;
    }

    try {
        await apiCall('/api/auth/setup', {
            method: 'POST',
            body: JSON.stringify({ master_password: password })
        });

        showToast('Master password set successfully');
        state.isAuthenticated = true;
        showScreen('main');
        await loadData();
    } catch (error) {
        console.error('Setup failed:', error);
    }
});

elements.loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const password = document.getElementById('login-password').value;

    try {
        await apiCall('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ master_password: password })
        });

        showToast('Login successful');
        state.isAuthenticated = true;
        showScreen('main');
        await loadData();
    } catch (error) {
        console.error('Login failed:', error);
    }
});

elements.logoutBtn.addEventListener('click', async () => {
    try {
        await apiCall('/api/auth/logout', { method: 'POST' });
        state.isAuthenticated = false;
        state.passwords = [];
        state.categories = [];
        showScreen('login');
        showToast('Logged out successfully');
    } catch (error) {
        console.error('Logout failed:', error);
    }
});

// Data Loading
async function loadData() {
    await Promise.all([loadCategories(), loadPasswords()]);
}

async function loadCategories() {
    try {
        state.categories = await apiCall('/api/categories');
        renderCategories();
    } catch (error) {
        console.error('Failed to load categories:', error);
    }
}

async function loadPasswords(categoryId = null, searchQuery = null) {
    try {
        let url = '/api/passwords';
        const params = new URLSearchParams();

        if (categoryId) params.append('category_id', categoryId);
        if (searchQuery) params.append('search', searchQuery);

        if (params.toString()) {
            url += `?${params.toString()}`;
        }

        state.passwords = await apiCall(url);
        renderPasswords();
    } catch (error) {
        console.error('Failed to load passwords:', error);
    }
}

// Rendering
function renderCategories() {
    elements.categoriesList.innerHTML = '';

    // All passwords category
    const allItem = document.createElement('div');
    allItem.className = `category-item ${!state.currentCategory ? 'active' : ''}`;
    allItem.innerHTML = `
        <span class="category-name">All Passwords</span>
        <span class="category-count">${state.passwords.length}</span>
    `;
    allItem.addEventListener('click', () => selectCategory(null));
    elements.categoriesList.appendChild(allItem);

    // Individual categories
    state.categories.forEach(category => {
        const count = state.passwords.filter(p => p.category_id === category.id).length;
        const item = document.createElement('div');
        item.className = `category-item ${state.currentCategory === category.id ? 'active' : ''}`;
        item.innerHTML = `
            <span class="category-color" style="background-color: ${category.color}"></span>
            <span class="category-name">${category.name}</span>
            <span class="category-count">${count}</span>
        `;
        item.addEventListener('click', () => selectCategory(category.id));
        elements.categoriesList.appendChild(item);
    });
}

function selectCategory(categoryId) {
    state.currentCategory = categoryId;
    const category = state.categories.find(c => c.id === categoryId);
    elements.currentCategoryTitle.textContent = category ? category.name : 'All Passwords';
    loadPasswords(categoryId);
    renderCategories();
}

function renderPasswords() {
    elements.passwordsList.innerHTML = '';
    elements.passwordCount.textContent = state.passwords.length;

    if (state.passwords.length === 0) {
        elements.emptyState.classList.remove('hidden');
        elements.passwordsList.classList.add('hidden');
        return;
    }

    elements.emptyState.classList.add('hidden');
    elements.passwordsList.classList.remove('hidden');

    state.passwords.forEach(password => {
        const card = document.createElement('div');
        card.className = 'password-card';
        card.innerHTML = `
            <div class="password-card-header">
                <div class="password-card-title">${password.title}</div>
                ${password.category_name ? `<span class="password-card-category" style="background-color: ${password.category_color}">${password.category_name}</span>` : ''}
            </div>
            <div class="password-card-info">
                ${password.username ? `<div class="password-card-field"><strong>User:</strong> ${password.username}</div>` : ''}
                ${password.url ? `<div class="password-card-field"><strong>URL:</strong> ${password.url}</div>` : ''}
            </div>
        `;
        card.addEventListener('click', () => viewPassword(password.id));
        elements.passwordsList.appendChild(card);
    });
}

// Search
let searchTimeout;
elements.searchInput.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    const query = e.target.value.trim();

    searchTimeout = setTimeout(() => {
        if (query) {
            loadPasswords(null, query);
            elements.currentCategoryTitle.textContent = 'Search Results';
            state.currentCategory = null;
            renderCategories();
        } else {
            loadPasswords(state.currentCategory);
            const category = state.categories.find(c => c.id === state.currentCategory);
            elements.currentCategoryTitle.textContent = category ? category.name : 'All Passwords';
        }
    }, 300);
});

// Password Modal
elements.addPasswordBtn.addEventListener('click', () => openPasswordModal());

function openPasswordModal(password = null) {
    const modal = elements.passwordModal;
    const form = document.getElementById('password-form');

    document.getElementById('modal-title').textContent = password ? 'Edit Password' : 'Add Password';
    document.getElementById('password-id').value = password ? password.id : '';
    document.getElementById('password-title').value = password ? password.title : '';
    document.getElementById('password-username').value = password ? password.username || '' : '';
    document.getElementById('password-password').value = '';
    document.getElementById('password-url').value = password ? password.url || '' : '';
    document.getElementById('password-notes').value = password ? password.notes || '' : '';
    document.getElementById('password-category').value = password ? password.category_id || '' : '';
    document.getElementById('password-master').value = '';

    // Populate category dropdown
    const categorySelect = document.getElementById('password-category');
    categorySelect.innerHTML = '<option value="">No Category</option>';
    state.categories.forEach(cat => {
        const option = document.createElement('option');
        option.value = cat.id;
        option.textContent = cat.name;
        categorySelect.appendChild(option);
    });

    if (password && password.category_id) {
        categorySelect.value = password.category_id;
    }

    modal.classList.remove('hidden');
}

function closePasswordModal() {
    elements.passwordModal.classList.add('hidden');
}

document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', () => {
        closePasswordModal();
        closeGeneratorModal();
        closeViewModal();
    });
});

document.getElementById('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const id = document.getElementById('password-id').value;
    const title = document.getElementById('password-title').value;
    const username = document.getElementById('password-username').value;
    const password = document.getElementById('password-password').value;
    const url = document.getElementById('password-url').value;
    const notes = document.getElementById('password-notes').value;
    const categoryId = document.getElementById('password-category').value || null;
    const masterPassword = document.getElementById('password-master').value;

    const data = {
        title,
        username,
        password,
        url,
        notes,
        category_id: categoryId ? parseInt(categoryId) : null,
        master_password: masterPassword
    };

    try {
        if (id) {
            await apiCall(`/api/passwords/${id}`, {
                method: 'PUT',
                body: JSON.stringify(data)
            });
            showToast('Password updated successfully');
        } else {
            await apiCall('/api/passwords', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            showToast('Password added successfully');
        }

        closePasswordModal();
        await loadPasswords(state.currentCategory);
        renderCategories();
    } catch (error) {
        console.error('Failed to save password:', error);
    }
});

// Password visibility toggle
document.getElementById('toggle-password').addEventListener('click', () => {
    const input = document.getElementById('password-password');
    input.type = input.type === 'password' ? 'text' : 'password';
});

// Password Generator
document.getElementById('generate-password').addEventListener('click', () => {
    elements.generatorModal.classList.remove('hidden');
    generatePassword();
});

function closeGeneratorModal() {
    elements.generatorModal.classList.add('hidden');
}

async function generatePassword() {
    const length = parseInt(document.getElementById('gen-length').value);
    const useUppercase = document.getElementById('gen-uppercase').checked;
    const useLowercase = document.getElementById('gen-lowercase').checked;
    const useDigits = document.getElementById('gen-digits').checked;
    const useSymbols = document.getElementById('gen-symbols').checked;

    try {
        const result = await apiCall('/api/generate-password', {
            method: 'POST',
            body: JSON.stringify({
                length,
                use_uppercase: useUppercase,
                use_lowercase: useLowercase,
                use_digits: useDigits,
                use_symbols: useSymbols
            })
        });

        document.getElementById('generated-password').value = result.password;
    } catch (error) {
        console.error('Failed to generate password:', error);
    }
}

document.getElementById('gen-length').addEventListener('input', (e) => {
    document.getElementById('length-value').textContent = e.target.value;
});

document.getElementById('regenerate-btn').addEventListener('click', generatePassword);

document.getElementById('use-generated-btn').addEventListener('click', () => {
    const generatedPassword = document.getElementById('generated-password').value;
    document.getElementById('password-password').value = generatedPassword;
    closeGeneratorModal();
});

document.getElementById('copy-generated').addEventListener('click', () => {
    const input = document.getElementById('generated-password');
    input.select();
    document.execCommand('copy');
    showToast('Password copied to clipboard');
});

// View Password Modal
async function viewPassword(passwordId) {
    const password = state.passwords.find(p => p.id === passwordId);
    if (!password) return;

    state.currentPassword = password;

    document.getElementById('view-title').textContent = password.title;
    document.getElementById('view-password-title').textContent = password.title;
    document.getElementById('view-password-username').textContent = password.username || '-';
    document.getElementById('view-password-password').value = '••••••••••••';
    document.getElementById('view-password-url').textContent = password.url || '-';
    document.getElementById('view-password-category').textContent = password.category_name || '-';
    document.getElementById('view-password-notes').textContent = password.notes || '-';
    document.getElementById('view-master-password').value = '';

    elements.viewModal.classList.remove('hidden');
}

function closeViewModal() {
    elements.viewModal.classList.add('hidden');
    state.currentPassword = null;
}

document.getElementById('decrypt-btn').addEventListener('click', async () => {
    const masterPassword = document.getElementById('view-master-password').value;

    if (!masterPassword) {
        showToast('Please enter master password', 'error');
        return;
    }

    try {
        const result = await apiCall(`/api/passwords/decrypt/${state.currentPassword.id}`, {
            method: 'POST',
            body: JSON.stringify({ master_password: masterPassword })
        });

        document.getElementById('view-password-password').value = result.password;
        showToast('Password decrypted');
    } catch (error) {
        console.error('Failed to decrypt password:', error);
    }
});

document.getElementById('reveal-password').addEventListener('click', () => {
    const input = document.getElementById('view-password-password');
    input.type = input.type === 'password' ? 'text' : 'password';
});

document.getElementById('copy-password').addEventListener('click', () => {
    const input = document.getElementById('view-password-password');
    if (input.value === '••••••••••••') {
        showToast('Please decrypt the password first', 'error');
        return;
    }
    input.select();
    document.execCommand('copy');
    showToast('Password copied to clipboard');
});

document.getElementById('edit-password-btn').addEventListener('click', () => {
    closeViewModal();
    openPasswordModal(state.currentPassword);
});

document.getElementById('delete-password-btn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to delete this password?')) {
        return;
    }

    try {
        await apiCall(`/api/passwords/${state.currentPassword.id}`, {
            method: 'DELETE'
        });

        showToast('Password deleted successfully');
        closeViewModal();
        await loadPasswords(state.currentCategory);
        renderCategories();
    } catch (error) {
        console.error('Failed to delete password:', error);
    }
});

// Add Category
elements.addCategoryBtn.addEventListener('click', async () => {
    const name = prompt('Enter category name:');

    if (!name) return;

    const colors = ['#3B82F6', '#10B981', '#F59E0B', '#8B5CF6', '#EF4444', '#EC4899', '#14B8A6', '#F97316'];
    const color = colors[Math.floor(Math.random() * colors.length)];

    try {
        await apiCall('/api/categories', {
            method: 'POST',
            body: JSON.stringify({ name, color })
        });

        showToast('Category added successfully');
        await loadCategories();
    } catch (error) {
        console.error('Failed to add category:', error);
    }
});

// Initialize
checkAuthStatus();
