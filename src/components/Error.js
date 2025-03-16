import React from 'react';

const Error = ({ message }) => {
    return (
        <div>
            <h2>Error</h2>
            <p style={{ color: 'red' }}>{message}</p>
            <p><a href="/">Go back to Login</a></p>
        </div>
    );
};

export default Error; 