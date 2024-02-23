window.setTimeout(function() {
    $(".alert").fadeTo(500, 0).slideUp(500, function(){
        $(this).remove(); 
    });
}, 3000);

document.getElementById('copy-icon').addEventListener('click', function() {
    var alertBox = document.createElement('div');
    alertBox.className = 'alert alert-info alert-dismissible fade show pop';
    alertBox.setAttribute('role', 'alert');
    alertBox.textContent = 'Link copied to clipboard!';
    var parentElement = document.getElementById('event-details-top');
    parentElement.insertBefore(alertBox, parentElement.firstChild);
});