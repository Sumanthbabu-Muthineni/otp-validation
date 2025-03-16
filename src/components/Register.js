import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import './styles.css';

const Register = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [companyName, setCompanyName] = useState('');
    const [age, setAge] = useState('');
    const [dob, setDob] = useState('');
    const [image, setImage] = useState(null);
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [imagePreview, setImagePreview] = useState(null);
    const [passwordStrength, setPasswordStrength] = useState({
        score: 0,
        message: '',
        color: '#ccc'
    });
    const navigate = useNavigate();

    // Password strength checker
    useEffect(() => {
        if (!password) {
            setPasswordStrength({
                score: 0,
                message: '',
                color: '#ccc'
            });
            return;
        }

        // Check password strength
        let score = 0;
        let message = '';
        let color = '';

        // Length check
        if (password.length >= 8) score += 1;
        
        // Complexity checks
        if (/[A-Z]/.test(password)) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^A-Za-z0-9]/.test(password)) score += 1;

        // Set message and color based on score
        switch (score) {
            case 0:
            case 1:
                message = 'Very Weak';
                color = '#e74c3c';
                break;
            case 2:
                message = 'Weak';
                color = '#e67e22';
                break;
            case 3:
                message = 'Moderate';
                color = '#f1c40f';
                break;
            case 4:
                message = 'Strong';
                color = '#2ecc71';
                break;
            case 5:
                message = 'Very Strong';
                color = '#27ae60';
                break;
            default:
                message = '';
                color = '#ccc';
        }

        setPasswordStrength({ score, message, color });
    }, [password]);

    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setImage(file);
            // Create preview URL
            const reader = new FileReader();
            reader.onloadend = () => {
                setImagePreview(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleRegister = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        
        // Validate password strength
        if (passwordStrength.score < 3) {
            setError('Please choose a stronger password for better security.');
            setIsLoading(false);
            return;
        }
        
        const formData = new FormData();
        formData.append('name', name);
        formData.append('email', email);
        formData.append('password', password);
        formData.append('companyName', companyName);
        formData.append('age', age);
        formData.append('dob', dob);
        if (image) formData.append('image', image);

        try {
            const response = await axios.post(`${process.env.REACT_APP_API_URL}/users/register`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            });
            if (response.data.success) {
                navigate('/thank-you');
            } else {
                setError('Registration failed. Please try again.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Registration failed. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="container">
            <div className="form-container">
                <h2>Create Your Account</h2>
                {error && <div className="error-message">{error}</div>}
                
                <form onSubmit={handleRegister}>
                    <input
                        type="text"
                        placeholder="Full Name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        required
                        aria-label="Full Name"
                    />
                    <input
                        type="email"
                        placeholder="Email Address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        aria-label="Email Address"
                    />
                    <div className="password-field">
                        <input
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            aria-label="Password"
                        />
                        {password && (
                            <div className="password-strength">
                                <div className="strength-bar">
                                    <div 
                                        className="strength-indicator" 
                                        style={{ 
                                            width: `${(passwordStrength.score / 5) * 100}%`,
                                            backgroundColor: passwordStrength.color 
                                        }}
                                    ></div>
                                </div>
                                <span style={{ color: passwordStrength.color }}>
                                    {passwordStrength.message}
                                </span>
                                {passwordStrength.score < 3 && (
                                    <p className="password-hint">
                                        Use at least 8 characters with uppercase letters, lowercase letters, numbers, and symbols.
                                    </p>
                                )}
                            </div>
                        )}
                    </div>
                    <input
                        type="text"
                        placeholder="Company Name (Optional)"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                        aria-label="Company Name"
                    />
                    <input
                        type="number"
                        placeholder="Age (Optional)"
                        value={age}
                        onChange={(e) => setAge(e.target.value)}
                        aria-label="Age"
                    />
                    <input
                        type="date"
                        placeholder="Date of Birth (Optional)"
                        value={dob}
                        onChange={(e) => setDob(e.target.value)}
                        aria-label="Date of Birth"
                    />
                    
                    <div style={{ marginBottom: '10px' }}>
                        <label htmlFor="profile-image" style={{ display: 'block', marginBottom: '8px', textAlign: 'left', color: '#555' }}>
                            Profile Image
                        </label>
                        <input
                            id="profile-image"
                            type="file"
                            accept="image/png, image/jpeg"
                            onChange={handleImageChange}
                            required
                            aria-label="Profile Image"
                        />
                        
                        {imagePreview && (
                            <div style={{ marginTop: '10px', textAlign: 'center' }}>
                                <img 
                                    src={imagePreview} 
                                    alt="Preview" 
                                    style={{ 
                                        maxWidth: '100%', 
                                        maxHeight: '150px', 
                                        borderRadius: '8px',
                                        border: '1px solid #ddd' 
                                    }} 
                                />
                            </div>
                        )}
                    </div>
                    
                    <button 
                        type="submit" 
                        disabled={isLoading || passwordStrength.score < 3}
                        className={passwordStrength.score < 3 ? 'button-disabled' : ''}
                    >
                        {isLoading ? 'Creating Account...' : 'Create Account'}
                    </button>
                </form>
                
                <p>
                    Already have an account? <Link to="/">Log In</Link>
                </p>
            </div>
        </div>
    );
};

export default Register;