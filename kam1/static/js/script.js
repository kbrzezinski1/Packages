function validate_first_name(txt)
{
    let result = /^([A-Z{PL}][a-z{pl}]{2,20})?$/.test(txt.value);
    if(!result){
        txt.style.borderColor = "red";
        return false
    }
    txt.style.borderColor = "green";
    return true
}

function validate_last_name(txt)
{
    let result = /^([A-Z{PL}][a-z{pl}]{2,20})?$/.test(txt.value);
    if(!result){
        txt.style.borderColor = "red";
        return false
    }
    txt.style.borderColor = "green";
    return true
}

function validate_login(txt)
{
    let result = /^([a-z]{3,12})?$/.test(txt.value);
    
    if(!result){
        txt.style.borderColor = "red";
        return false
    }
    txt.style.borderColor = "green";
    return true
}


async function getResults(txt) {


    let response = await fetch('https://infinite-hamlet-29399.herokuapp.com/check/'+  txt.value)       
    if (response.ok) {
        let text = await response.text();
        console.log(text)
        if(text.includes("taken")){
            console.log(text)
            txt.style.borderColor = "red";
        }
      } else {
        alert("HTTP-Error: " + response.status);
      }

}
function validate_sex(txt)
{
    let result = /^([MFmf])?$/.test(txt.value);
    if(!result){
        txt.style.borderColor = "red";
        return false
    }
    txt.style.borderColor = "green";
    return true
}

function validate_password(txt)
{
    if(txt.value.length<8){
        txt.style.borderColor = "red";
        return false
    }
    txt.style.borderColor = "green";
    return true
}
function validate_password_confirm(txt1, txt2){
    if(txt1.value!=txt2.value){
        txt1.style.borderColor = "red";
        return false
    }
    txt1.style.borderColor = "green";
    return true
}
 
    const button = document.getElementById("button");
    const form = document.getElementById('formularz');
    let error
    window.flag = true
    var firstName = document.getElementById("firstname")
    var lastName = document.getElementById("lastname")
    var login = document.getElementById("login")
    var sex = document.getElementById("sex")
    var password = document.getElementById("password")
    var password2 = document.getElementById("password2")
    
    firstName.addEventListener("input", function(ev){
        validate_first_name(firstName)

    });

    lastName.addEventListener("input", function(ev){
        validate_last_name(lastName)
    });

    login.addEventListener("input", function(ev){
        validate_login(login)
        getResults(login)
    });

    sex.addEventListener("input", function(ev){
        validate_sex(sex)
    });
    
    form.addEventListener("submit", ev => {    

        ev.preventDefault()       
        error = false
        removeMessage(firstName)
        if(!validate_first_name(firstName)){
            showMessage(firstName, "Imię musi składać się z co najmniej 3 liter i zaczynać od dużej litery")
            error = true
        }
        removeMessage(lastName)
        if(!validate_last_name(lastName)){
            showMessage(lastName, "Nazwisko musi składać się z co najmniej 3 liter i zaczynać od dużej litery")
            error = true
        }
        removeMessage(login)
        if(login.style.borderColor == "red"){
            if(!validate_login(login)){
                showMessage(login, "Login musi składać się z 3 do 12 liter i samych małych liter")
                error = true
            }
            else {
                showMessage(login, "Login jest zajęty")
                error = true
        }}
        removeMessage(sex)
        if(!validate_sex(sex)){
            showMessage(sex, "Płeć musi być uzupełniona jako M lub K")
            error = true
        }
        removeMessage(password)
        if(!validate_password(password)){
            showMessage(password, "Hasło musi mieć minimum 8 znaków")
            error = true
        }
        removeMessage(password2)
        if(!validate_password_confirm(password2, password)){
            showMessage(password2, "Hasła muszą być identyczne")
            error = true
        }
        if(!error){
            ev.target.submit();
        }        
    });

function showMessage(field, text) {
    removeMessage(field);
    const div = document.createElement("div");
    div.classList.add("form-error-text");
    div.innerText = text;
    if (field.nextElementSibling === null) {
        field.parentElement.appendChild(div);
    } else {
        if (!field.nextElementSibling.classList.contains("form-error-text")) {
            field.parentElement.insertBefore(div, field.nextElementSibling);
        }
    }
}

function removeMessage(field) {
    const errorText = field.nextElementSibling;
    if (errorText !== null) {
        if (errorText.classList.contains("form-error-text")) {
            errorText.remove();
        }
    }
}