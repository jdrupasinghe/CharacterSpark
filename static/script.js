function validateSignup() {
    let username = document.getElementById("username").value;
    let password = document.getElementById("password").value;
    let re_password = document.getElementById("re_password").value;

    let usernameError = document.getElementById("username-error");
    let passwordError = document.getElementById("password-error");
    let repasswordError = document.getElementById("repassword-error");

    usernameError.style.display = "none";
    passwordError.style.display = "none";
    repasswordError.style.display = "none";

    let valid = true;

    if (!/^[a-zA-Z0-9]+$/.test(username)) {
        usernameError.innerText = "Username can only contain letters and numbers.";
        usernameError.style.display = "block";
        valid = false;
    }

    if (password.length < 8) {
        passwordError.innerText = "Password must be at least 8 characters long.";
        passwordError.style.display = "block";
        valid = false;
    }

    if (password !== re_password) {
        repasswordError.innerText = "Passwords do not match!";
        repasswordError.style.display = "block";
        valid = false;
    }

    return valid;
}

