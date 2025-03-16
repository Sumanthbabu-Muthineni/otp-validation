import React from 'react';
import { useNavigate } from 'react-router-dom';
import './styles.css';

const ThankYou = () => {
    const navigate = useNavigate();

    const handleGoBackToLogin = () => {
        navigate('/');
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
                        stroke="#4BB543" 
                        strokeWidth="2" 
                        strokeLinecap="round" 
                        strokeLinejoin="round"
                        style={{ margin: '0 auto 20px' }}
                    >
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                        <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                    
                    <h2>Registration Successful!</h2>
                    <p>Your account has been created successfully. You can now log in with your credentials.</p>
                    
                    <button 
                        onClick={handleGoBackToLogin}
                        style={{ marginTop: '20px' }}
                    >
                        Go to Login
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ThankYou;
