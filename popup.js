document.addEventListener('DOMContentLoaded', () => {
    const views = {
        setup: document.getElementById('setup-view'),
        login: document.getElementById('login-view'),
        main: document.getElementById('main-view'),
    };

    // --- State ---
    let masterKey = null; // This will hold the CryptoKey object after login

    // --- UI Elements ---
    const setupPass = document.getElementById('setup-master-password');
    const confirmPass = document.getElementById('confirm-master-password');
    const saveMasterPassBtn = document.getElementById('save-master-password-btn');
    const loginPass = document.getElementById('login-master-password');
    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const getUrlBtn = document.getElementById('get-url-btn');
    const websiteUrlInput = document.getElementById('website-url');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const addCredentialBtn = document.getElementById('add-credential-btn');
    const credentialsList = document.getElementById('credentials-list');
    const toast = document.getElementById('toast');

    // --- Cryptography Functions ---

    // Derives a key from a master password and a salt using PBKDF2
    async function deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // Encrypts data (string) using the derived master key
    async function encryptData(key, data) {
        const enc = new TextEncoder();
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // GCM recommended IV size is 12 bytes
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            key,
            enc.encode(data)
        );
        
        // Combine IV and encrypted data for storage
        const encryptedData = new Uint8Array(iv.length + encryptedContent.byteLength);
        encryptedData.set(iv);
        encryptedData.set(new Uint8Array(encryptedContent), iv.length);

        // Return as base64 string for easy storage in JSON
        return btoa(String.fromCharCode.apply(null, encryptedData));
    }

    // Decrypts base64 encoded data using the derived master key
    async function decryptData(key, encryptedBase64) {
        try {
            const encryptedData = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
            const iv = encryptedData.slice(0, 12);
            const encryptedContent = encryptedData.slice(12);
            
            const decryptedContent = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                },
                key,
                encryptedContent
            );

            const dec = new TextDecoder();
            return dec.decode(decryptedContent);
        } catch (e) {
            console.error("Decryption failed:", e);
            return null; // Indicates a wrong password or corrupted data
        }
    }


    // --- UI and Application Logic ---
    
    function showView(viewName) {
        Object.values(views).forEach(v => v.classList.add('hidden'));
        if (views[viewName]) {
            views[viewName].classList.remove('hidden');
        }
    }
    
    // Show a toast notification
    function showToast(message) {
        toast.textContent = message;
        toast.classList.remove('opacity-0');
        setTimeout(() => {
            toast.classList.add('opacity-0');
        }, 2000);
    }

    // Renders the list of credentials in the main view
    async function renderCredentials() {
        credentialsList.innerHTML = '';
        const { vault } = await chrome.storage.local.get('vault');
        if (!vault) return;

        const decryptedVault = await decryptData(masterKey, vault);
        if (!decryptedVault) return;
        
        const credentials = JSON.parse(decryptedVault);

        if (credentials.length === 0) {
            credentialsList.innerHTML = `<p class="text-slate-500 text-center text-sm">No credentials saved yet.</p>`;
            return;
        }

        credentials.forEach((cred, index) => {
            const div = document.createElement('div');
            div.className = 'bg-slate-700 p-3 rounded-lg flex items-center justify-between';
            div.innerHTML = `
                <div class="flex-1 overflow-hidden">
                    <p class="font-bold truncate text-slate-300" title="${cred.website}">${cred.website}</p>
                    <p class="text-sm text-slate-400 truncate" title="${cred.username}">${cred.username}</p>
                </div>
                <div class="flex items-center space-x-2 ml-2">
                    <button data-password="${cred.password}" title="Copy Password" class="copy-btn p-2 hover:bg-slate-600 rounded-full transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                    <button data-index="${index}" title="Delete" class="delete-btn p-2 hover:bg-rose-500 rounded-full transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                    </button>
                </div>
            `;
            credentialsList.appendChild(div);
        });
    }

    // --- Event Listeners ---

    // Initial check to see if a vault is set up
    chrome.storage.local.get('salt', ({ salt }) => {
        if (salt) {
            showView('login');
        } else {
            showView('setup');
        }
    });

    // Setup: Save master password
    saveMasterPassBtn.addEventListener('click', async () => {
        if (setupPass.value !== confirmPass.value) {
            alert("Passwords do not match.");
            return;
        }
        if (setupPass.value.length < 8) {
            alert("Master password should be at least 8 characters long.");
            return;
        }

        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const key = await deriveKey(setupPass.value, salt);
        const emptyVault = await encryptData(key, JSON.stringify([]));

        // Store salt and the empty encrypted vault
        await chrome.storage.local.set({
            salt: btoa(String.fromCharCode.apply(null, salt)),
            vault: emptyVault,
        });

        masterKey = key;
        showView('main');
        await renderCredentials();
    });
    
    // Login
    loginBtn.addEventListener('click', async () => {
        const { salt } = await chrome.storage.local.get('salt');
        if (!salt) return;
        
        const saltBytes = new Uint8Array(atob(salt).split('').map(c => c.charCodeAt(0)));
        const key = await deriveKey(loginPass.value, saltBytes);
        
        // Test decryption to verify password
        const { vault } = await chrome.storage.local.get('vault');
        const decryptedVault = await decryptData(key, vault);

        if (decryptedVault) {
            masterKey = key;
            loginPass.value = '';
            showView('main');
            await renderCredentials();
        } else {
            alert("Wrong master password!");
        }
    });
    loginPass.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') loginBtn.click();
    });


    // Logout
    logoutBtn.addEventListener('click', () => {
        masterKey = null;
        showView('login');
    });

    // Get current tab's URL
    getUrlBtn.addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0] && tabs[0].url) {
                const url = new URL(tabs[0].url);
                websiteUrlInput.value = url.hostname;
            }
        });
    });

    // Add a new credential
    addCredentialBtn.addEventListener('click', async () => {
        const website = websiteUrlInput.value.trim();
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!website || !username || !password) {
            alert("All fields are required.");
            return;
        }

        const { vault } = await chrome.storage.local.get('vault');
        const decryptedVault = await decryptData(masterKey, vault);
        const credentials = JSON.parse(decryptedVault);

        credentials.push({ website, username, password });
        
        const newEncryptedVault = await encryptData(masterKey, JSON.stringify(credentials));
        await chrome.storage.local.set({ vault: newEncryptedVault });

        websiteUrlInput.value = '';
        usernameInput.value = '';
        passwordInput.value = '';

        await renderCredentials();
    });

    // Event delegation for copy and delete buttons
    credentialsList.addEventListener('click', async (e) => {
        const copyBtn = e.target.closest('.copy-btn');
        const deleteBtn = e.target.closest('.delete-btn');

        if (copyBtn) {
            const passwordToCopy = copyBtn.dataset.password;
            navigator.clipboard.writeText(passwordToCopy).then(() => {
                showToast("Password copied!");
            });
        }

        if (deleteBtn) {
            if (!confirm("Are you sure you want to delete this credential?")) return;
            
            const index = parseInt(deleteBtn.dataset.index, 10);
            
            const { vault } = await chrome.storage.local.get('vault');
            const decryptedVault = await decryptData(masterKey, vault);
            let credentials = JSON.parse(decryptedVault);
            
            credentials.splice(index, 1); // Remove the item

            const newEncryptedVault = await encryptData(masterKey, JSON.stringify(credentials));
            await chrome.storage.local.set({ vault: newEncryptedVault });
            await renderCredentials();
        }
    });
});
