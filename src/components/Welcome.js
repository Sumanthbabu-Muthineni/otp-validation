import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import './styles.css';

const Welcome = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [deleteError, setDeleteError] = useState('');
    const [deleteLoading, setDeleteLoading] = useState(false);

    useEffect(() => {
        // Get user data from location state or fetch from API
        const userFromState = location.state?.user;
        const token = localStorage.getItem('token');
        
        if (userFromState) {
            setUserData(userFromState);
            setLoading(false);
        } else if (token) {
            // If no user data in state, try to fetch from API
            const fetchUserData = async () => {
                try {
                    const response = await axios.get(`${process.env.REACT_APP_API_URL}/users/me`, {
                        headers: {
                            Authorization: `Bearer ${token}`
                        }
                    });
                    if (response.data.success) {
                        setUserData(response.data.user);
                    } else {
                        // If no user data, redirect to login
                        navigate('/');
                    }
                } catch (error) {
                    console.error('Error fetching user data:', error);
                    navigate('/');
                } finally {
                    setLoading(false);
                }
            };
            
            fetchUserData();
        } else {
            navigate('/');
        }
    }, [location.state, navigate]);

    const handleLogout = () => {
        // Clear any stored tokens
        localStorage.removeItem('token');
        navigate('/');
    };

    const handleDeleteAccount = async () => {
        setDeleteLoading(true);
        setDeleteError('');
        
        try {
            const token = localStorage.getItem('token');
            const response = await axios.delete(`${process.env.REACT_APP_API_URL}/users/delete-account`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });
            
            if (response.data.success) {
                localStorage.removeItem('token');
                navigate('/', { state: { message: 'Your account has been successfully deleted.' } });
            } else {
                setDeleteError('Failed to delete account. Please try again.');
            }
        } catch (error) {
            setDeleteError(error.response?.data?.message || 'Failed to delete account. Please try again.');
        } finally {
            setDeleteLoading(false);
        }
    };

    // Extract name from email if name is not available
    const displayName = userData?.name || userData?.email?.split('@')[0] || 'User';

    if (loading) {
        return (
            <div className="container">
                <div className="form-container">
                    <p>Loading...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="form-container">
                <div style={{ textAlign: 'center' }}>
                    <div style={{ 
                        width: '80px',
                        height: '80px',
                        borderRadius: '50%',
                        backgroundColor: '#4a90e2',
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '32px',
                        fontWeight: 'bold',
                        margin: '0 auto 20px'
                    }}>
                        {displayName.charAt(0).toUpperCase()}
                    </div>
                    
                    <h2>Welcome, {displayName}!</h2>
                    <p>You have successfully logged in.</p>
                    
                    <div style={{ 
                        backgroundColor: '#f8f9fa',
                        padding: '15px',
                        borderRadius: '8px',
                        marginTop: '20px',
                        textAlign: 'left'
                    }}>
                        <p style={{ margin: '5px 0', color: '#333' }}>
                            <strong>Email:</strong> {userData?.email || 'N/A'}
                        </p>
                        {userData?.companyName && (
                            <p style={{ margin: '5px 0', color: '#333' }}>
                                <strong>Company:</strong> {userData.companyName}
                            </p>
                        )}
                        {userData?.age && (
                            <p style={{ margin: '5px 0', color: '#333' }}>
                                <strong>Age:</strong> {userData.age}
                            </p>
                        )}
                    </div>
                    
                    <div style={{ marginTop: '25px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <button 
                            onClick={handleLogout}
                            className="primary-button"
                        >
                            Logout
                        </button>
                        
                        {!showDeleteConfirm ? (
                            <button 
                                onClick={() => setShowDeleteConfirm(true)}
                                className="danger-button"
                            >
                                Delete Account
                            </button>
                        ) : (
                            <div className="delete-confirmation">
                                <p style={{ color: '#e74c3c', fontWeight: 'bold' }}>
                                    Are you sure you want to delete your account? This action cannot be undone.
                                </p>
                                {deleteError && <div className="error-message">{deleteError}</div>}
                                <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                                    <button 
                                        onClick={() => setShowDeleteConfirm(false)}
                                        className="secondary-button"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        onClick={handleDeleteAccount}
                                        className="danger-button"
                                        disabled={deleteLoading}
                                    >
                                        {deleteLoading ? 'Deleting...' : 'Confirm Delete'}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Welcome;