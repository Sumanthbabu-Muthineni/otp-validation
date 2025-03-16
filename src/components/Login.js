import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import OtpVerification from './OtpVerification';
import './styles.css'; // Import your CSS file

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isOtpSent, setIsOtpSent] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        
        try {
            const response = await axios.post(`${process.env.REACT_APP_API_URL}/users/login`, { email, password });
            if (response.data.success) {
                setIsOtpSent(true);
            } else {
                setError('Sorry, we can\'t log you in.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Sorry, we can\'t log you in.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="container">
            <div className="form-container">
                {!isOtpSent ? (
                    <>
                        <h2>Welcome Back</h2>
                        {error && <div className="error-message">{error}</div>}
                        
                        <form onSubmit={handleLogin}>
                            <input
                                type="email"
                                placeholder="Email Address"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                                aria-label="Email Address"
                            />
                            <input
                                type="password"
                                placeholder="Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                aria-label="Password"
                            />
                            <button 
                                type="submit" 
                                disabled={isLoading}
                            >
                                {isLoading ? 'Logging in...' : 'Log In'}
                            </button>
                        </form>
                        
                        <div className="form-divider">
                            <span>OR</span>
                        </div>
                        
                        <p>
                            Don't have an account? <Link to="/register">Create Account</Link>
                        </p>
                    </>
                ) : (
                    <OtpVerification email={email} />
                )}
            </div>
        </div>
    );
};

export default Login;