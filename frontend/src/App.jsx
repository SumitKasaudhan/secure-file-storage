// src/App.jsx - Using Custom CSS Classes
import React, { Component } from 'react';
import { Upload, Download, Lock, Unlock, User, LogOut, FileText, Shield, Key, AlertCircle, Trash2 } from 'lucide-react';
import axios from 'axios';
import './App.css';

const API_URL = "https://secure-file-storage-ll88.onrender.com/api";

class App extends Component {
    constructor(props) {
        super(props);

        this.state = {
            currentView: 'login',
            user: null,
            token: localStorage.getItem('token'),
            files: [],
            activityLog: [],
            authForm: {
                username: '',
                password: '',
                role: 'user'
            },
            uploadFile: null,
            uploadStatus: '',
            encryptionKey: '',
            loading: false
        };
    }

    componentDidMount() {
        if (this.state.token) {
            axios.defaults.headers.common['Authorization'] = 'Bearer ' + this.state.token;
            this.fetchUserData();
            this.fetchFiles();
        }
    }

    fetchUserData = () => {
        try {
            const userData = JSON.parse(localStorage.getItem('user'));
            if (userData) {
                this.setState({ user: userData, currentView: 'dashboard' });
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
            this.handleLogout();
        }
    }

    fetchFiles = () => {
        const self = this;
        axios.get(API_URL + '/files')
            .then(function (response) {
                self.setState({ files: response.data });
            })
            .catch(function (error) {
                console.error('Error fetching files:', error);
                self.showStatus('Error loading files', 'error');
            });
    }

    fetchLogs = () => {
        const self = this;
        axios.get(API_URL + '/logs')
            .then(function (response) {
                self.setState({ activityLog: response.data });
            })
            .catch(function (error) {
                console.error('Error fetching logs:', error);
                self.showStatus('Error loading logs', 'error');
            });
    }

    showStatus = (message, type) => {
        const self = this;
        this.setState({ uploadStatus: { message: message, type: type || 'success' } });
        setTimeout(function () {
            self.setState({ uploadStatus: '' });
        }, 3000);
    }

    handleLogin = () => {
        const self = this;
        this.setState({ loading: true });

        axios.post(API_URL + '/auth/login', {
            username: this.state.authForm.username,
            password: this.state.authForm.password
        })
            .then(function (response) {
                const token = response.data.token;
                const user = response.data.user;

                self.setState({ token: token, user: user });
                localStorage.setItem('token', token);
                localStorage.setItem('user', JSON.stringify(user));

                axios.defaults.headers.common['Authorization'] = 'Bearer ' + token;

                self.setState({ currentView: 'dashboard', loading: false });
                self.showStatus('Login successful!', 'success');
                self.fetchFiles();
            })
            .catch(function (error) {
                const message = error.response && error.response.data && error.response.data.message
                    ? error.response.data.message
                    : 'Login failed';
                self.showStatus(message, 'error');
                self.setState({ loading: false });
            });
    }

    handleRegister = () => {
        const self = this;
        this.setState({ loading: true });

        axios.post(API_URL + '/auth/register', {
            username: this.state.authForm.username,
            password: this.state.authForm.password,
            role: this.state.authForm.role
        })
            .then(function (response) {
                self.showStatus('Registration successful! Please login.', 'success');
                self.setState({
                    currentView: 'login',
                    authForm: { username: '', password: '', role: 'user' },
                    loading: false
                });
            })
            .catch(function (error) {
                const message = error.response && error.response.data && error.response.data.message
                    ? error.response.data.message
                    : 'Registration failed';
                self.showStatus(message, 'error');
                self.setState({ loading: false });
            });
    }

    handleFileUpload = () => {
        const self = this;

        if (!this.state.uploadFile) {
            this.showStatus('Please select a file', 'error');
            return;
        }

        if (!this.state.encryptionKey) {
            this.showStatus('Please enter an encryption key', 'error');
            return;
        }

        this.setState({ loading: true });

        const formData = new FormData();
        formData.append('file', this.state.uploadFile);
        formData.append('encryptionKey', this.state.encryptionKey);

        axios.post(API_URL + '/files/upload', formData, {
            headers: { 'Content-Type': 'multipart/form-data' }
        })
            .then(function (response) {
                self.showStatus('✓ File encrypted and uploaded successfully!', 'success');
                self.setState({
                    uploadFile: null,
                    encryptionKey: '',
                    loading: false
                });

                const fileInput = document.querySelector('input[type="file"]');
                if (fileInput) fileInput.value = '';

                self.fetchFiles();
            })
            .catch(function (error) {
                const message = error.response && error.response.data && error.response.data.message
                    ? error.response.data.message
                    : 'Upload failed';
                self.showStatus(message, 'error');
                self.setState({ loading: false });
            });
    }

    handleFileDownload = (file, key) => {
        const self = this;
        this.setState({ loading: true });

        axios.post(
            API_URL + '/files/download/' + file._id,
            { decryptionKey: key },
            { responseType: 'blob' }
        )
            .then(function (response) {
                const url = window.URL.createObjectURL(new Blob([response.data]));
                const link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', file.originalName);
                document.body.appendChild(link);
                link.click();
                link.remove();
                window.URL.revokeObjectURL(url);

                self.showStatus('✓ File downloaded successfully!', 'success');
                self.setState({ loading: false });
            })
            .catch(function (error) {
                const message = error.response && error.response.data && error.response.data.message
                    ? error.response.data.message
                    : 'Download failed - Wrong key?';
                self.showStatus(message, 'error');
                self.setState({ loading: false });
            });
    }

    handleFileDelete = (fileId) => {
        const self = this;

        if (!window.confirm('Are you sure you want to delete this file?')) return;

        this.setState({ loading: true });

        axios.delete(API_URL + '/files/' + fileId)
            .then(function (response) {
                self.showStatus('File deleted successfully', 'success');
                self.setState({ loading: false });
                self.fetchFiles();
            })
            .catch(function (error) {
                const message = error.response && error.response.data && error.response.data.message
                    ? error.response.data.message
                    : 'Delete failed';
                self.showStatus(message, 'error');
                self.setState({ loading: false });
            });
    }

    handleLogout = () => {
        this.setState({
            user: null,
            token: null,
            currentView: 'login',
            authForm: { username: '', password: '', role: 'user' }
        });
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        delete axios.defaults.headers.common['Authorization'];
    }

    handleAuthFormChange = (field, value) => {
        const authForm = Object.assign({}, this.state.authForm);
        authForm[field] = value;
        this.setState({ authForm: authForm });
    }

    render() {
        const self = this;

        return React.createElement('div', { className: 'app-container' },
            React.createElement('div', { className: 'max-width-container' },
                // Header
                React.createElement('div', { className: 'app-header' },
                    React.createElement('div', { className: 'header-content' },
                        React.createElement('div', { className: 'header-left' },
                            React.createElement(Shield, { className: 'header-icon' }),
                            React.createElement('div', null,
                                React.createElement('h1', { className: 'header-title' }, 'Secure File Storage System'),
                                React.createElement('p', { className: 'header-subtitle' }, 'AES-256 + RSA Encryption | Role-Based Access Control')
                            )
                        ),
                        this.state.user && React.createElement('div', { className: 'header-right' },
                            React.createElement('div', { className: 'user-info' },
                                React.createElement('p', { className: 'user-name' }, this.state.user.username),
                                React.createElement('p', { className: 'user-role' }, this.state.user.role)
                            ),
                            React.createElement('button', {
                                onClick: this.handleLogout,
                                className: 'logout-btn'
                            },
                                React.createElement(LogOut, { className: 'action-icon' }),
                                'Logout'
                            )
                        )
                    )
                ),

                React.createElement('div', { className: 'main-content' },
                    // Status Message
                    this.state.uploadStatus && React.createElement('div', {
                        className: 'status-message ' + (this.state.uploadStatus.type === 'success' ? 'status-success' : 'status-error')
                    },
                        React.createElement(AlertCircle, { className: 'status-icon' }),
                        this.state.uploadStatus.message
                    ),

                    // Login View
                    this.state.currentView === 'login' && React.createElement(LoginView, {
                        authForm: this.state.authForm,
                        loading: this.state.loading,
                        onFormChange: this.handleAuthFormChange,
                        onLogin: this.handleLogin,
                        onSwitchToRegister: function () { self.setState({ currentView: 'register' }); }
                    }),

                    // Register View
                    this.state.currentView === 'register' && React.createElement(RegisterView, {
                        authForm: this.state.authForm,
                        loading: this.state.loading,
                        onFormChange: this.handleAuthFormChange,
                        onRegister: this.handleRegister,
                        onSwitchToLogin: function () { self.setState({ currentView: 'login' }); }
                    }),

                    // Dashboard View
                    this.state.currentView === 'dashboard' && React.createElement(DashboardView, {
                        uploadFile: this.state.uploadFile,
                        encryptionKey: this.state.encryptionKey,
                        loading: this.state.loading,
                        user: this.state.user,
                        filesCount: this.state.files.length,
                        onFileChange: function (e) {
                            if (e.target.files && e.target.files[0]) {
                                self.setState({ uploadFile: e.target.files[0] });
                            }
                        },
                        onKeyChange: function (e) { self.setState({ encryptionKey: e.target.value }); },
                        onUpload: this.handleFileUpload,
                        onSwitchToFiles: function () {
                            self.setState({ currentView: 'files' });
                            self.fetchFiles();
                        },
                        onSwitchToLogs: function () {
                            self.setState({ currentView: 'logs' });
                            self.fetchLogs();
                        }
                    }),

                    // Files View
                    this.state.currentView === 'files' && React.createElement(FilesView, {
                        files: this.state.files,
                        user: this.state.user,
                        loading: this.state.loading,
                        onDownload: this.handleFileDownload,
                        onDelete: this.handleFileDelete,
                        onBackToDashboard: function () { self.setState({ currentView: 'dashboard' }); }
                    }),

                    // Logs View
                    this.state.currentView === 'logs' && this.state.user && this.state.user.role === 'admin' &&
                    React.createElement(LogsView, {
                        logs: this.state.activityLog,
                        onBackToDashboard: function () { self.setState({ currentView: 'dashboard' }); }
                    })
                ),

                // Footer
                React.createElement('div', { className: 'app-footer' },
                    React.createElement('p', { className: 'footer-text' }, '🔒 All files are encrypted with AES-256 | 🔑 RSA key encryption | 👤 JWT authentication')
                )
            )
        );
    }
}

// Login View Component
class LoginView extends Component {
    render() {
        const props = this.props;
        return React.createElement('div', { className: 'auth-container fade-in' },
            React.createElement('div', { className: 'auth-content' },
                React.createElement('div', { className: 'auth-header' },
                    React.createElement(Lock, { className: 'auth-icon' }),
                    React.createElement('h2', { className: 'auth-title' }, 'Secure Login'),
                    React.createElement('p', { className: 'auth-description' }, 'Access your encrypted files')
                ),

                React.createElement('div', { className: 'auth-form' },
                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' }, 'Username'),
                        React.createElement('input', {
                            type: 'text',
                            value: props.authForm.username,
                            onChange: function (e) { props.onFormChange('username', e.target.value); },
                            onKeyPress: function (e) { if (e.key === 'Enter') props.onLogin(); },
                            className: 'form-input',
                            placeholder: 'Enter your username'
                        })
                    ),

                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' }, 'Password'),
                        React.createElement('input', {
                            type: 'password',
                            value: props.authForm.password,
                            onChange: function (e) { props.onFormChange('password', e.target.value); },
                            onKeyPress: function (e) { if (e.key === 'Enter') props.onLogin(); },
                            className: 'form-input',
                            placeholder: 'Enter your password'
                        })
                    ),

                    React.createElement('button', {
                        onClick: props.onLogin,
                        disabled: props.loading,
                        className: 'btn-primary'
                    },
                        React.createElement(Unlock, { className: 'action-icon' }),
                        props.loading ? 'Logging in...' : 'Login'
                    )
                ),

                React.createElement('div', { className: 'auth-switch' },
                    React.createElement('button', {
                        onClick: props.onSwitchToRegister,
                        className: 'auth-switch-btn'
                    }, "Don't have an account? Register here")
                ),

                React.createElement('div', { className: 'demo-credentials' },
                    React.createElement('p', { className: 'demo-title' }, 'Demo Credentials:'),
                    React.createElement('p', { className: 'demo-text' }, 'Username: testuser | Password: test123')
                )
            )
        );
    }
}

// Register View Component
class RegisterView extends Component {
    render() {
        const props = this.props;
        return React.createElement('div', { className: 'auth-container fade-in' },
            React.createElement('div', { className: 'auth-content' },
                React.createElement('div', { className: 'auth-header' },
                    React.createElement(User, { className: 'auth-icon' }),
                    React.createElement('h2', { className: 'auth-title' }, 'Create Account'),
                    React.createElement('p', { className: 'auth-description' }, 'Register for secure file storage')
                ),

                React.createElement('div', { className: 'auth-form' },
                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' }, 'Username'),
                        React.createElement('input', {
                            type: 'text',
                            value: props.authForm.username,
                            onChange: function (e) { props.onFormChange('username', e.target.value); },
                            className: 'form-input',
                            placeholder: 'Choose a username'
                        })
                    ),

                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' }, 'Password'),
                        React.createElement('input', {
                            type: 'password',
                            value: props.authForm.password,
                            onChange: function (e) { props.onFormChange('password', e.target.value); },
                            className: 'form-input',
                            placeholder: 'Choose a strong password'
                        })
                    ),

                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' }, 'Role'),
                        React.createElement('select', {
                            value: props.authForm.role,
                            onChange: function (e) { props.onFormChange('role', e.target.value); },
                            className: 'form-select'
                        },
                            React.createElement('option', { value: 'user' }, 'User'),
                            React.createElement('option', { value: 'admin' }, 'Admin')
                        )
                    ),

                    React.createElement('button', {
                        onClick: props.onRegister,
                        disabled: props.loading,
                        className: 'btn-primary'
                    }, props.loading ? 'Registering...' : 'Register')
                ),

                React.createElement('div', { className: 'auth-switch' },
                    React.createElement('button', {
                        onClick: props.onSwitchToLogin,
                        className: 'auth-switch-btn'
                    }, 'Already have an account? Login here')
                )
            )
        );
    }
}

// Dashboard View Component  
class DashboardView extends Component {
    render() {
        const props = this.props;
        return React.createElement('div', { className: 'dashboard-container fade-in' },
            // Navigation Tabs
            React.createElement('div', { className: 'nav-tabs' },
                React.createElement('button', { className: 'nav-tab nav-tab-active' }, 'Upload Files'),
                React.createElement('button', {
                    onClick: props.onSwitchToFiles,
                    className: 'nav-tab nav-tab-inactive'
                }, 'My Files (' + props.filesCount + ')'),
                props.user.role === 'admin' && React.createElement('button', {
                    onClick: props.onSwitchToLogs,
                    className: 'nav-tab nav-tab-inactive'
                }, 'Activity Logs')
            ),

            // Upload Section
            React.createElement('div', { className: 'upload-section' },
                React.createElement('h3', { className: 'section-header' },
                    React.createElement(Upload, { className: 'section-icon' }),
                    'Upload & Encrypt File'
                ),

                React.createElement('div', { className: 'upload-form' },
                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'form-label' },
                            'Select File ',
                            props.uploadFile && React.createElement('span', { className: 'file-selected' }, '✓ ' + props.uploadFile.name)
                        ),
                        React.createElement('input', {
                            type: 'file',
                            onChange: props.onFileChange,
                            className: 'file-input'
                        }),
                        React.createElement('p', { className: 'file-hint' }, 'Supports all file types (max 10MB)')
                    ),

                    React.createElement('div', { className: 'form-group' },
                        React.createElement('label', { className: 'label-with-icon' },
                            React.createElement(Key, { className: 'label-icon' }),
                            'Encryption Key (Remember this to decrypt later!)'
                        ),
                        React.createElement('input', {
                            type: 'password',
                            value: props.encryptionKey,
                            onChange: props.onKeyChange,
                            placeholder: 'Enter a strong encryption key',
                            className: 'form-input'
                        })
                    ),

                    React.createElement('button', {
                        onClick: props.onUpload,
                        disabled: props.loading,
                        className: 'btn-upload'
                    },
                        React.createElement(Lock, { className: 'action-icon' }),
                        props.loading ? 'Encrypting...' : 'Encrypt & Upload'
                    )
                ),

                React.createElement('div', { className: 'security-note' },
                    React.createElement('p', { className: 'security-text' },
                        '🔐 Security Note: Files are encrypted using AES-256 before storage. Keep your encryption key safe - it cannot be recovered!'
                    )
                )
            )
        );
    }
}

// Files View Component
class FilesView extends Component {
    render() {
        const props = this.props;
        return React.createElement('div', { className: 'files-container fade-in' },
            React.createElement('div', { className: 'files-header' },
                React.createElement('h3', { className: 'files-title' },
                    React.createElement(FileText, { className: 'title-icon' }),
                    props.user.role === 'admin' ? 'All Files' : 'My Files'
                ),
                React.createElement('button', {
                    onClick: props.onBackToDashboard,
                    className: 'btn-back'
                }, 'Back to Upload')
            ),

            React.createElement('div', { className: 'files-grid' },
                props.files.map(function (file) {
                    return React.createElement(FileCard, {
                        key: file._id,
                        file: file,
                        onDownload: props.onDownload,
                        onDelete: props.onDelete,
                        userRole: props.user.role,
                        loading: props.loading
                    });
                }),

                props.files.length === 0 && React.createElement('div', { className: 'empty-state' },
                    React.createElement(FileText, { className: 'empty-icon' }),
                    React.createElement('p', { className: 'empty-text' }, 'No files uploaded yet'),
                    React.createElement('button', {
                        onClick: props.onBackToDashboard,
                        className: 'btn-empty-action'
                    }, 'Upload Your First File')
                )
            )
        );
    }
}

// Logs View Component
class LogsView extends Component {
    render() {
        const props = this.props;
        return React.createElement('div', { className: 'logs-container fade-in' },
            React.createElement('div', { className: 'files-header' },
                React.createElement('h3', { className: 'files-title' }, 'Activity Logs'),
                React.createElement('button', {
                    onClick: props.onBackToDashboard,
                    className: 'btn-back'
                }, 'Back to Dashboard')
            ),

            React.createElement('div', { className: 'logs-list' },
                props.logs.map(function (log, idx) {
                    return React.createElement('div', { key: idx, className: 'log-item' },
                        React.createElement('div', { className: 'log-content' },
                            React.createElement('div', { className: 'log-info' },
                                React.createElement('p', { className: 'log-action' }, log.action),
                                React.createElement('p', { className: 'log-details' }, log.details)
                            ),
                            React.createElement('div', { className: 'log-meta' },
                                React.createElement('p', { className: 'log-user' }, log.user && log.user.username ? log.user.username : 'System'),
                                React.createElement('p', { className: 'log-timestamp' }, new Date(log.timestamp).toLocaleString())
                            )
                        )
                    );
                }),

                props.logs.length === 0 && React.createElement('div', { className: 'empty-state' },
                    React.createElement('p', { className: 'empty-text' }, 'No activity logs yet')
                )
            )
        );
    }
}

// FileCard Component
class FileCard extends Component {
    constructor(props) {
        super(props);
        this.state = {
            decryptKey: '',
            showDecrypt: false
        };
    }

    formatSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    render() {
        const props = this.props;
        const self = this;

        return React.createElement('div', { className: 'file-card' },
            React.createElement('div', { className: 'file-card-content' },
                React.createElement('div', { className: 'file-info' },
                    React.createElement('div', { className: 'file-icon-wrapper' },
                        React.createElement(Lock, { className: 'file-icon' })
                    ),
                    React.createElement('div', { className: 'file-details' },
                        React.createElement('h4', { className: 'file-name' }, props.file.originalName),
                        React.createElement('div', { className: 'file-metadata' },
                            React.createElement('p', { className: 'file-meta-item' }, 'Size: ' + this.formatSize(props.file.size)),
                            React.createElement('p', { className: 'file-meta-item' }, 'Type: ' + props.file.mimeType),
                            React.createElement('p', { className: 'file-meta-item' }, 'Uploaded by: ' + (props.file.uploadedBy && props.file.uploadedBy.username ? props.file.uploadedBy.username : 'Unknown')),
                            React.createElement('p', { className: 'file-meta-item' }, 'Date: ' + new Date(props.file.uploadDate).toLocaleString())
                        )
                    )
                ),

                React.createElement('div', { className: 'file-actions' },
                    React.createElement('button', {
                        onClick: function () { self.setState({ showDecrypt: !self.state.showDecrypt }); },
                        className: 'btn-download'
                    },
                        React.createElement(Download, { className: 'action-icon' }),
                        'Download'
                    ),
                    React.createElement('button', {
                        onClick: function () { props.onDelete(props.file._id); },
                        disabled: props.loading,
                        className: 'btn-delete'
                    },
                        React.createElement(Trash2, { className: 'action-icon' })
                    )
                )
            ),

            this.state.showDecrypt && React.createElement('div', { className: 'decrypt-section' },
                React.createElement('label', { className: 'decrypt-label' }, 'Enter Decryption Key:'),
                React.createElement('div', { className: 'decrypt-form' },
                    React.createElement('input', {
                        type: 'password',
                        value: this.state.decryptKey,
                        onChange: function (e) { self.setState({ decryptKey: e.target.value }); },
                        placeholder: 'Enter your encryption key',
                        className: 'decrypt-input'
                    }),
                    React.createElement('button', {
                        onClick: function () {
                            props.onDownload(props.file, self.state.decryptKey);
                            self.setState({ decryptKey: '', showDecrypt: false });
                        },
                        disabled: props.loading,
                        className: 'btn-decrypt'
                    },
                        React.createElement(Unlock, { className: 'action-icon' }),
                        'Decrypt'
                    )
                )
            )
        );
    }
}

export default App;