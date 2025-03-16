import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import './styles.css';

const VerificationSent = () => {
    const [email, setEmail] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleResendVerification = async (e) => {
        e.preventDefault();
        
        if (!email) {
            setError('Please enter your email address');
            return;
        }
        
        setIsLoading(true);
        setError('');
        setMessage('');
        
        try {
            const response = await axios.post(`${process.env.REACT_APP_API_URL}/users/resend-verification`, { email });
            
            if (response.data.success) {
                setMessage('Verification email has been resent. Please check your inbox.');
                setEmail('');
            } else {
                setError('Failed to resend verification email. Please try again.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to resend verification email. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="container">
            <div className="form-container">
                <div style={{ textAlign: 'center' }}>
                    <svg 
                        width="80" 
                        height="80" 
                        viewBox="0 0 24 24" 
                        fill="none" 
                        stroke="#4a90e2" 
                        strokeWidth="2" 
                        strokeLinecap="round" 
                        strokeLinejoin="round"
                        style={{ margin: '0 auto 20px' }}
                    >
                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                        <polyline points="22,6 12,13 2,6"></polyline>
                    </svg>
                    
                    <h2>Verify Your Email</h2>
                    <p>We've sent a verification link to your email address. Please check your inbox and click the link to verify your account.</p>
                    
                    <div style={{ 
                        backgroundColor: '#f8f9fa',
                        padding: '15px',
                        borderRadius: '8px',
                        marginTop: '20px',
                        marginBottom: '20px'
                    }}>
                        <p style={{ margin: '5px 0', color: '#333' }}>
                            <strong>Didn't receive the email?</strong>
                        </p>
                        <p style={{ fontSize: '14px', color: '#666' }}>
                            Check your spam folder or request a new verification link below.
                        </p>
                    </div>
                    
                    {message && (
                        <div style={{ 
                            backgroundColor: '#d4edda', 
                            color: '#155724', 
                            padding: '10px', 
                            borderRadius: '4px',
                            marginBottom: '15px'
                        }}>
                            {message}
                        </div>
                    )}
                    
                    {error && <div className="error-message">{error}</div>}
                    
                    <form onSubmit={handleResendVerification} style={{ maxWidth: '300px', margin: '0 auto' }}>
                        <input
                            type="email"
                            placeholder="Enter your email address"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <button 
                            type="submit" 
                            disabled={isLoading}
                        >
                            {isLoading ? 'Sending...' : 'Resend Verification Email'}
                        </button>
                    </form>
                    
                    <p style={{ marginTop: '20px' }}>
                        <Link to="/">Return to Login</Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default VerificationSent; 