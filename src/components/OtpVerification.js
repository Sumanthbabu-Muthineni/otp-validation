import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './styles.css'; // Import your CSS file

const OtpVerification = ({ email }) => {
    const [otp, setOtp] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [timeLeft, setTimeLeft] = useState(300); // 5 minutes in seconds
    const navigate = useNavigate();

    useEffect(() => {
        // Countdown timer for OTP expiration
        if (timeLeft <= 0) return;
        
        const timer = setInterval(() => {
            setTimeLeft(prev => prev - 1);
        }, 1000);
        
        return () => clearInterval(timer);
    }, [timeLeft]);

    const formatTime = (seconds) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
    };

    const handleVerifyOtp = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        
        try {
            const response = await axios.post(`${process.env.REACT_APP_API_URL}/users/verify-otp`, { email, otp });
            if (response.data.success) {
                // Get user data from response if available
                const userData = response.data.user || { email };
                navigate('/welcome', { state: { user: userData } });
            } else {
                setError('Invalid OTP. Please try again.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Error verifying OTP. Please try again.');
            console.error('Verification error:', err.response?.data);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div>
            <h2>Verify Your Identity</h2>
            <p>We've sent a 6-digit code to <strong>{email}</strong></p>
            
            {error && <div className="error-message">{error}</div>}
            
            <form onSubmit={handleVerifyOtp}>
                <input
                    type="text"
                    placeholder="Enter 6-digit OTP"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    maxLength={6}
                    pattern="\d{6}"
                    required
                    aria-label="OTP Code"
                />
                
                <div style={{ fontSize: '14px', color: timeLeft < 60 ? '#e74c3c' : '#666', margin: '10px 0' }}>
                    Time remaining: {formatTime(timeLeft)}
                </div>
                
                <button 
                    type="submit" 
                    disabled={isLoading || timeLeft <= 0}
                >
                    {isLoading ? 'Verifying...' : 'Verify OTP'}
                </button>
            </form>
            
            {timeLeft <= 0 && (
                <p style={{ marginTop: '15px' }}>
                    OTP expired. <a href="/">Return to login</a>
                </p>
            )}
        </div>
    );
};

export default OtpVerification; 