function LoginUserForm() {
    const username = document.getElementById('id_Username').value;
    const password = document.getElementById('id_Password').value;

    const credientials = {
        username: username,
        password: password
    }

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(credientials)
    }).then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/dashboard'
                alert('Login Sucessful')
            } else {
                alert('Login failed. Check your Credentials.')
            }
        }).catch(error => {
            console.error('Error:', error);
        });
}   